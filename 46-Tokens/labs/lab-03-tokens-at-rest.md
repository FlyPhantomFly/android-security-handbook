# Lab 03 — Tokens at Rest

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-anatomy-of-a-token.md),
[Chapter 46 §3.7 and §5.9–§5.10](../README.md#37-where-a-token-lives-on-android--the-four-options),
[33-Storage §5.3](../../33-Storage/README.md), [49-KeyStore §1.3](../../49-KeyStore/README.md)

---

## Objective

Find a token on a device, and then — the part that separates a report from a list — decide
whether finding it is worth writing down.

By the end you will have swept an app's storage from four different access levels, watched
the same token appear in four different places with four different severities, and applied
§5.10's five conditions to each. You will also have written the sentence that most mobile
reports get wrong, correctly.

> **Safety**
> Every token here is one you minted (Lab 01 and Lab 02's issuer) and installed into an app
> you built. Do not sweep an app signed into a real account, and on a daily-driver phone do
> not enumerate apps beyond the one you are testing. Read-only commands only: this lab runs
> no `rm`, no `pm clear`, and no `settings put`.

---

## Part 0 — Establish your access level FIRST

This is the step that decides how to read everything else, and it is the one people do
last.

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell "su -c id"                   # root? (AOSP emulator: adb shell "su 0 id")
adb shell run-as com.example.app id    # debuggable?
```

Measured on the device attached while this chapter was written — an **i9000S, Android 13 /
API 33, not rooted**:

``` <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- verbatim captured session on a device with no `su` at all; the quoting is moot here and the output is the genuine measurement -->
$ adb shell su -c id
/system/bin/sh: su: inaccessible or not found
$ adb shell run-as com.synergyenf ls
run-as: package not debuggable: com.synergyenf
$ adb shell ls -ld /data/data/com.synergyenf
ls: /data/data/com.synergyenf: Permission denied
```

All three doors shut. That is the **correct** behaviour of a stock device and the normal
starting position on a real engagement.

**Q1.** Given those three outputs, what can you still see? List everything reachable from an
`adb shell` at uid 2000 with no root and a non-debuggable app. (There are at least five
things, and they are all in the sweep script.)

**Q2.** Someone hands you a report that says *"No authentication tokens were found in
insecure storage."* What single question do you ask before believing it?

Run the chapter's sweep, which prints its access level before any results for exactly this
reason:

```bash
# host
CH46="path/to/Android-Security-Handbook/46-Tokens"
bash "$CH46/scripts/token-storage-sweep.sh" com.example.app
```

Reference output on the unrooted i9000S:

```
------------------------------------------------------------------------
  0. Access level -- read this before believing anything below
------------------------------------------------------------------------
  [ ] device        i9000S, API 33
  [ ] root          no  (/system/bin/sh: su: inaccessible or not found)
  [ ] run-as        no  (run-as: package not debuggable: com.synergyenf)
  [ ] package           userId=10156
  [ ] backup flag   ALLOW_BACKUP not in pkgFlags -- allowBackup is false

  [!] NO ACCESS TO PRIVATE STORAGE. Sections 1 and 2 below will find nothing, and that
  [!] is a fact about this shell, not about the app. Do not write 'no tokens stored'.
```

**Q3.** The script prints the access level *before* the results rather than after. Why does
the order matter? What behavioural failure is it designed to prevent in the person reading
the output?

---

## Part 1 — Build a target you are allowed to break

You need an app that stores tokens badly. Build one — you cannot report on a mechanism you
have not constructed, and you must not practise on someone else's app.

### 1.1 The app

A single-activity app whose only job is to store the token from Lab 01's issuer four
different ways.

```java
// TokenLab.java -- a deliberately leaky token store. Build as a debuggable APK.
package com.pentest.ch46lab;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;

public class TokenLab extends Activity {

    private static final String TAG = "TokenLab";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        // Paste a token you minted in Lab 01 or Lab 02. NEVER a real one.
        String access  = getIntent().getStringExtra("access_token");
        String refresh = getIntent().getStringExtra("refresh_token");
        if (access == null) { finish(); return; }

        // (1) plaintext SharedPreferences -- the common case
        getSharedPreferences("auth", Context.MODE_PRIVATE).edit()
                .putString("access_token", access)
                .putString("refresh_token", refresh)
                .apply();

        // (2) a file in the private dir
        try (FileOutputStream fos = openFileOutput("session.json", Context.MODE_PRIVATE)) {
            fos.write(("{\"access\":\"" + access + "\"}").getBytes());
        } catch (Exception e) { Log.e(TAG, "write failed", e); }

        // (3) SQLite -- so you can see what a DELETE leaves behind
        SQLiteDatabase db = openOrCreateDatabase("session.db", MODE_PRIVATE, null);
        db.execSQL("CREATE TABLE IF NOT EXISTS tokens (id INTEGER PRIMARY KEY, tok TEXT)");
        db.execSQL("INSERT INTO tokens (tok) VALUES (?)", new Object[]{ access });
        db.execSQL("INSERT INTO tokens (tok) VALUES (?)", new Object[]{ refresh });
        db.close();

        // (4) external storage -- OUTSIDE the private sandbox
        File ext = new File(getExternalFilesDir(null), "token.txt");
        try (FileOutputStream fos = new FileOutputStream(ext)) {
            fos.write(access.getBytes());
        } catch (Exception e) { Log.e(TAG, "ext write failed", e); }

        // (5) and the classic escape route
        Log.d(TAG, "stored access=" + access);

        finish();
    }

    /** "Logout": clears preferences and deletes the rows. Watch what survives. */
    public void logout() {
        getSharedPreferences("auth", Context.MODE_PRIVATE).edit().clear().apply();
        SQLiteDatabase db = openOrCreateDatabase("session.db", MODE_PRIVATE, null);
        db.execSQL("DELETE FROM tokens");
        db.close();
    }
}
```

Manifest essentials:

```xml
<!-- AndroidManifest.xml -->
<application
    android:allowBackup="true"
    android:debuggable="true"
    android:label="TokenLab">
    <activity android:name=".TokenLab" android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
</application>
```

### 1.2 Building it without Gradle

[`30-Activities/examples/build.sh`](../../30-Activities/examples/build.sh) has a complete
no-Gradle pipeline — `aapt2 link`, `javac --release 8`, `d8`, `zipalign`, `apksigner` —
that builds **out of tree** so no `.apk` or `.dex` reaches this repository. Copy its
approach rather than re-deriving it.

> **The install trap, measured**
> On the Redmi device in this estate, `adb install` fails with
> `INSTALL_FAILED_USER_RESTRICTED: Install canceled by user` even though nobody cancelled
> anything. It is MIUI's "Install via USB" policy. `adb shell "su -c 'pm install -r
> /data/local/tmp/app.apk'"` works, because root is not subject to the gate.
> `30-Activities/examples/build.sh` detects this exact failure and falls back automatically.
>
> On the unrooted i9000S there is no root to fall back to. If your device refuses the
> install and offers no root, do Parts 2 and 3 on an emulator — the storage mechanics are
> identical and the whole point of Part 0 is that you record which platform produced which
> result.

### 1.3 Drive it

```bash
# host — feed it a token YOU minted
TOK=$(cat ~/ch46-gauntlet/tokens/genuine.jwt)
RT="opaque-refresh-$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"

adb shell am start -n com.pentest.ch46lab/.TokenLab \
    --es access_token "$TOK" --es refresh_token "$RT"
```

**Q4.** That command puts the token in an Intent extra. Chapter 29 measured that
`dumpsys` records broadcast extras in cleartext and that a test broadcast carrying
`token=SUPERSECRET123` was readable afterwards. Check whether the same is true for an
activity start on your device:

```bash
adb shell dumpsys activity activities | grep -i "access_token" | head
```

What did you find? What does that mean for **your own testing hygiene**, independent of any
finding about the app?

---

## Part 2 — Sweep it

```bash
# host
bash "$CH46/scripts/token-storage-sweep.sh" com.pentest.ch46lab
```

With `run-as` available (the app is debuggable) the sweep reaches private storage. Work
through each section.

### 2.1 SharedPreferences

```bash
# host
adb shell "run-as com.pentest.ch46lab ls -la /data/data/com.pentest.ch46lab/shared_prefs/"
adb shell "run-as com.pentest.ch46lab cat /data/data/com.pentest.ch46lab/shared_prefs/auth.xml"
```

**Q5.** Read the XML. The token is in plaintext. Before writing anything down, answer
§5.10's five conditions for it:

| Condition | Yes/No | Your evidence |
|---|---|---|
| Over-scoped | | |
| Long-lived | | |
| Replayable after logout | | |
| Accepted without verification | | |
| Readable by another app | | |

**Q6.** Now call `logout()` and re-read the file:

```bash
adb shell "run-as com.pentest.ch46lab ls -la /data/data/com.pentest.ch46lab/shared_prefs/"
```

Is there a `.bak` file? What is in it? Read
[§4.4](../README.md#44-sharedpreferencesimpl--when-the-token-actually-hits-the-disk) and
explain where it came from.

### 2.2 The SQLite WAL

This is the one people miss.

```bash
# host — pull all three files, not just the .db
for f in session.db session.db-wal session.db-shm; do
  adb shell "run-as com.pentest.ch46lab cat /data/data/com.pentest.ch46lab/databases/$f" > "$f" 2>/dev/null
done
ls -la session.db*

# SQL says the rows are gone
sqlite3 session.db "SELECT COUNT(*) FROM tokens;"

# the bytes say otherwise
strings session.db-wal | grep -o 'eyJ[A-Za-z0-9_-]*' | head
```

**Q7.** What did SQL report, and what did `strings` on the WAL report? Chapter 33 measured
this exact effect: *"A `logout` deleting 2 rows left all four secrets readable in a
61,832-byte `-wal` file while SQL reported them gone."* Reproduce it and record your own
numbers.

**Q8.** Why does this happen? (Read [33-Storage §3.10](../../33-Storage/README.md) if you
need the mechanism.) What would the app have to do for the delete to actually remove the
bytes?

### 2.3 External storage

```bash
# host — no root, no run-as needed
adb shell "ls -la /sdcard/Android/data/com.pentest.ch46lab/files/"
adb shell "cat /sdcard/Android/data/com.pentest.ch46lab/files/token.txt"
```

**Q9.** This one required **none** of the access levels from Part 0. What changes about the
severity? Which of the five conditions does it satisfy that the SharedPreferences copy does
not, and why?

**Q10.** On API 30+ scoped storage narrows who can read `/sdcard/Android/data/<pkg>/`. Find
out what it narrows it to on your device, and decide whether that changes your severity. Be
specific — "scoped storage protects it" is not an answer.

### 2.4 Logcat

```bash
# host
adb logcat -c
adb shell am start -n com.pentest.ch46lab/.TokenLab --es access_token "$TOK" --es refresh_token "$RT"
sleep 2
adb logcat -d | grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' | sort -u
```

**Q11.** Who can read logcat on a modern Android device? Enumerate, precisely: which
permission, which uid, which OEM exceptions. Then decide the severity, and say what changes
if the app also links a crash-reporting SDK.

### 2.5 Backup

```bash
# host
adb shell "dumpsys package com.pentest.ch46lab" | grep -E 'ALLOW_BACKUP|dataDir'
adb backup -f backup.ab com.pentest.ch46lab 2>&1 | head -3
```

**Q12.** What happened? On many modern devices `adb backup` is restricted or removed
entirely. Does its failure prove the token is not backed up? What is the *other* backup path
and how would you check it?

**Q13.** Add `android:dataExtractionRules="@xml/rules"` to the manifest with only a
`<cloud-backup>` exclusion, rebuild, and check again. What is still exposed? (§8.1's warning
has the answer, but work it out from the documentation first.)

---

## Part 3 — Now make it harder, and see what changes

Replace storage option (1) with `EncryptedSharedPreferences`:

```kotlin
// Add to the app -- androidx.security:security-crypto
val masterKey = MasterKey.Builder(this)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
val prefs = EncryptedSharedPreferences.create(
    this, "auth_v2", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
prefs.edit().putString("access_token", access).apply()
```

Rebuild, re-run, re-sweep.

```bash
# host
adb shell "run-as com.pentest.ch46lab cat /data/data/com.pentest.ch46lab/shared_prefs/auth_v2.xml"
```

**Q14.** What do you see now? Is the key name readable? Is the value? Explain the difference
in terms of AES-SIV versus AES-GCM (§3.7 has the two schemes).

**Q15.** The file is now useless to anyone who copies it. Answer each of these separately:
- Does this stop an attacker who has a **backup** of the file? Why?
- Does this stop an attacker with **root** on the device? Why?
- Does this stop an attacker with **Frida** attached to the process? Why?

**Q16.** Write the sentence you would put in a report for an app that uses
`EncryptedSharedPreferences`, in a section titled "Positive observations". It must be
accurate about what it buys **and** what it does not. This is harder than it looks; iterate
until a sceptical reviewer could not attack either half.

**Q17.** Now find the plaintext copy. Options (2), (3), (4) and (5) are still leaking. Chapter
33 §5.4 calls this a vulnerability class in its own right — "the plaintext copy beside the
ciphertext". Write the finding for it, and explain why encrypting one store and not the
others is arguably *worse* than encrypting none, from a reviewer's point of view.

---

## Part 4 — Reachability, which is what decides severity

Presence is not reachability. This is [33-Storage §5.3](../../33-Storage/README.md)'s
method, applied to a token.

```bash
# host — with root, or from your emulator
adb shell "su -c 'ls -ldZ /data/data/com.pentest.ch46lab \
    /data/data/com.pentest.ch46lab/shared_prefs \
    /data/data/com.pentest.ch46lab/shared_prefs/auth.xml'"
```

Two gates must **both** allow the read:

**Gate 1 — DAC.** `open(2)` resolves a path one component at a time. A single ancestor
without `o+x` ends it, regardless of the file's own mode. Walk the whole path and record
each mode.

**Gate 2 — SELinux MCS.** Read the labels. An app's data directory carries per-app MCS
categories; a third-party app in a different category cannot read it even if DAC would
allow. Note the measured exception from chapter 33: `privapp_data_file` carries **no
per-app categories**, which is how an ordinary app with zero permissions read
`com.google.android.gms/shared_prefs/google_sdk_flags.xml` on a stock Enforcing device.

**Q18.** Fill this in for your lab app's `auth.xml`:

| Path component | Mode | Owner | SELinux label | Walkable by another app? |
|---|---|---|---|---|
| `/data/data` | | | | |
| `/data/data/com.pentest.ch46lab` | | | | |
| `.../shared_prefs` | | | | |
| `.../shared_prefs/auth.xml` | | | | |

**Q19.** Based on that table, is condition 5 ("readable by another app") satisfied? Prove
it or disprove it. The gold-standard proof is a second app with **zero permissions** that
tries the read — write one, and record what happens.

**Q20.** Now do the same for `/sdcard/Android/data/com.pentest.ch46lab/files/token.txt`.
Does the answer differ? Why?

---

## Part 5 — Write it up

You now have the same token in five places. Write five findings — or fewer, if you conclude
some of them are not findings, which is the correct answer for at least one.

For each, produce:

- **Title** — specific, not "insecure storage"
- **Severity** — with the §5.10 condition it rests on, named explicitly
- **Impact** — what an attacker gains that they did not already have
- **Evidence** — the command and its output, plus the access level it required
- **Remediation** — as code or configuration, not as advice
- **Caveat** — the access level required, stated in the finding itself

**Q21.** Which of the five did you decide is **not** a finding? Defend it. A reviewer will
push back, and the defence must be about what the attacker learned, not about how hard it
was to find.

**Q22.** Which one would you lead the report with? Why is that not the same as "the one
with the highest severity"?

**Q23.** Write the single sentence that most mobile reports get wrong:

> *"The application stores an authentication token in SharedPreferences."*

Replace it with a version that a competent reviewer would accept. It must name the
condition, cite the evidence, and state the access level required.

---

## Hints

<details>
<summary>Hint for Q1 — what an unrooted shell can still see</summary>

`dumpsys package <pkg>` (uid, flags, dataDir, permissions), `dumpsys account`, the whole of
`/sdcard` including `Android/data/<pkg>` on many API levels, `logcat`, `pm list packages`,
`am start` to drive the app, and the network — `adb reverse` gets you a listener the device
can reach with no root at all, which is how chapter 67 ran a live triage on an unrooted
phone.
</details>

<details>
<summary>Hint for Q7 — the WAL</summary>

SQLite in WAL mode appends changes to `-wal` and only folds them into the main database at a
checkpoint. A `DELETE` writes a *new version of the page* with the row removed; the old page
containing the row is still sitting in the WAL until it is overwritten.

So `SELECT` correctly reports zero rows — the query engine reads the current state — and the
bytes of the deleted row are still on the flash. Any storage review that queries the
database instead of reading its files misses this entirely.
</details>

<details>
<summary>Hint for Q14 — SIV versus GCM</summary>

AES-SIV is **deterministic**: the same plaintext key always encrypts to the same ciphertext.
That is required, because otherwise `getString("access_token")` could not find the entry.
The cost is that an observer learns when two entries have the same name, and can build a
dictionary of known preference names.

AES-GCM is **randomised and authenticated**: the same value encrypts differently every time,
and modifying the ciphertext causes decryption to fail rather than to produce
attacker-chosen bytes. That is right for values.
</details>

<details>
<summary>Hint for Q16 — the positive-observation sentence</summary>

Both halves must survive challenge. Something like:

> The application stores its refresh token in `EncryptedSharedPreferences`, with a master
> key generated in the Android Keystore. This means an attacker who obtains a *copy* of the
> preferences file — via a backup, a forensic image, or a path-traversal bug elsewhere in
> the app — cannot read it. It does **not** protect the token against code executing inside
> the application's own process: an attacker with root and an instrumentation framework
> calls the same getter and receives the same plaintext. The control raises the cost of
> **extraction**; it does not constrain **use**.

Then check the plaintext copies (Q17), because a positive observation about one store while
four others leak is a misleading positive.
</details>

<details>
<summary>Hint for Q23 — the sentence</summary>

Name the condition, cite the evidence, state the access level:

> The application's refresh token is stored in plaintext in
> `/data/data/com.example.app/shared_prefs/auth.xml` and **remains valid at the
> authorization server after the user logs out** (verified: HTTP 200 from
> `GET /v1/me` using a token captured before logout, replayed 4 minutes after). Because the
> token has a 90-day lifetime and no rotation, any copy of this file — obtained through a
> device backup, a lost or resold handset, or root access — grants uninterrupted account
> access for up to three months. Retrieving the file required `run-as`, which is available
> because the shipped build sets `android:debuggable="true"`.

Notice what carries the weight: **replayable after logout** plus **long-lived**. The
storage location is context, not the finding.
</details>

---

## Success criteria

- [ ] You established and recorded your access level **before** interpreting any result
- [ ] You built a target app rather than practising on somebody else's
- [ ] You found the token in all five locations
- [ ] You recovered a "deleted" token from the SQLite WAL and recorded the file size
- [ ] You found a `.bak` preferences file and can explain where it came from
- [ ] You switched one store to `EncryptedSharedPreferences` and can state precisely what
      changed and what did not
- [ ] You completed the reachability table in Part 4 with both DAC and SELinux
- [ ] You wrote a zero-permission proof-of-concept reader, or proved one could not work
- [ ] You decided that at least one of the five is **not** a finding, and can defend it
- [ ] You wrote the Q23 sentence and a sceptical reader could not attack either half
- [ ] Every token you handled was one you minted

---

## Debrief

1. Rank the five locations by severity and justify the ordering **without** referring to
   how hard each was to find.
2. Two of the five are reachable with no special access at all. Which, and what does that
   do to the threat model?
3. You are told the app will ship with `android:debuggable="false"`. Which of your five
   findings change severity, and by how much?
4. A developer proposes fixing everything by moving all five stores to
   `EncryptedSharedPreferences`. Which of your findings does that actually fix? Which does
   it not touch at all?
5. Explain to a developer why the logcat leak is a finding even though the token is stored
   correctly everywhere else.
6. §5.10 says a captured token from your own test account is not a finding. Every token in
   this lab was yours. So what, precisely, made any of these findings? Answer in terms of
   properties of the *system* rather than properties of your session.

---

## Next

[Lab 04 — CTF: The token that outlived its owner](lab-04-ctf-the-token-that-outlived-its-owner.md)
puts the issuer, the verifier and the device together, with four independent paths to the
flag and a severity argument at the end.
