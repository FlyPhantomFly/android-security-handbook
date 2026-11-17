# 27 — Content Providers — FAQ

Real questions learners ask, including the ones people are embarrassed to ask out loud.

---

### 1. I still don't get it — why can't one app just read another app's files?

Because Android gives every installed application its own Linux user ID. Your app runs as UID 10123
and its files under `/data/data/com.yourapp` are owned by UID 10123 with permissions that exclude
everyone else. The kernel enforces this, exactly as it would on a Linux server with two user accounts.
There is no Android-specific magic involved; it is ordinary POSIX file ownership.

So if the Contacts app wants to let you read contacts, it cannot "give you the file". It has to
run code that reads the file *as itself* and hands you the answer. That code is the content provider.

---

### 2. Is a content provider a database?

No. A content provider is an *interface* whose method names happen to be SQL-shaped. Behind it there
is usually a SQLite database, but it can equally be a file, a network cache, an in-memory list, a
hardware sensor, or nothing at all. `Settings.Global` is a content provider backed by an XML file.
`FileProvider` is a content provider backed by the filesystem with no database anywhere.

This distinction matters when testing: seeing `content://` does not guarantee that SQL injection is
possible, and seeing no injection does not mean there is nothing behind the URI.

---

### 3. What is an "authority" and who decides it?

The authority is the unique name that identifies one provider on the device — the
`com.example.app.provider` part of `content://com.example.app.provider/notes`. The developer chooses
it in the manifest, and by convention it is the package name plus a suffix.

It must be unique across the whole device. If you try to install an app declaring an authority that
another installed app already declares, the install fails with `INSTALL_FAILED_CONFLICTING_PROVIDER`.
That uniqueness requirement is also a minor attack consideration: an app that installs first "wins"
an authority name, so a hard-coded authority shared between two of a vendor's apps can be squatted.

---

### 4. Why does `adb shell content query` work but my test app gets a SecurityException?

Because `adb shell` runs as the `shell` user, UID 2000, which the platform grants a set of privileges
that no ordinary application has. Your test app runs as UID 10xxx with nothing special.

This is the single most important thing in the chapter for report quality. A `content query` that
succeeds from `adb shell` proves nothing about what an attacker's app can do. Always reproduce with
Drozer's agent or a small sideloaded APK before you write a finding.

---

### 5. My `content query` returns "Unknown URI". Have I failed?

No — you have succeeded at the more important step. `IllegalArgumentException: Unknown URI` is thrown
by the *provider's own code*, after the framework let you through the permission check. It means the
authority is right, you are authorised to talk to the provider, and only the path is wrong.

Compare that with `SecurityException: Permission Denial`, which means you never reached the provider's
code at all. The difference between those two messages is a reliable oracle, and it is how you brute
force paths.

---

### 6. What is the difference between `selection` and `selectionArgs`, really?

`selection` is a string of SQL that goes into the `WHERE` clause. `selectionArgs` is an array of
values that get substituted for `?` placeholders inside that string by SQLite itself, at the level of
the prepared statement, never by string concatenation.

```java
// Safe: the value is bound, never parsed as SQL
db.query("notes", null, "title = ?", new String[]{ userInput }, null, null, null);

// Unsafe: the value becomes part of the SQL text
db.rawQuery("SELECT * FROM notes WHERE title = '" + userInput + "'", null);
```

In the first form, if `userInput` is `' OR 1=1 --`, SQLite looks for a note whose title is literally
the string `' OR 1=1 --`. It is a value, not code.

---

### 7. If `selectionArgs` is safe, why is SQL injection still possible?

Because `selectionArgs` only protects *values in the `WHERE` clause*. Two other parameters go into
positions where SQLite does not allow bound parameters at all:

- `projection` becomes the column list after `SELECT`. You cannot write `SELECT ? FROM t` and bind a
  column name.
- `sortOrder` becomes the `ORDER BY` expression. You cannot bind that either.

So a developer who does everything right with `selectionArgs` still typically concatenates those two.
That is why the chapter insists on testing all three.

---

### 8. How do I inject through `sortOrder` if nothing comes back to me?

You use the query's success or failure as a one-bit output channel. SQLite evaluates the `ORDER BY`
expression, so you write an expression whose false branch raises an error:

```
CASE WHEN (SELECT substr(token,1,1) FROM session)='e'
     THEN _id
     ELSE abs(-9223372036854775808) END
```

`abs()` of the smallest 64-bit integer overflows and throws. So the query succeeding means your guess
was right, and the query failing means it was wrong. One bit per request. With a binary search over
the character set that is about seven requests per character, and each request over local IPC takes
milliseconds.

---

### 9. Why is `getType()` not permission-checked? That seems like a bug.

It is deliberate. The framework needs to ask "what type of data is at this URI?" to resolve
intents — for example, to decide which apps can handle `ACTION_VIEW` on a `content://` URI. If that
question required a permission, intent resolution would break for every app that has not yet been
granted access.

The consequence, which Android has since recognised, is that a provider computing its MIME type by
running a database query converts an unprotected call into a data read. Android 13 added
`getTypeAnonymous()` and routes untrusted callers there, so the platform now expects providers to
return a constant to untrusted callers. When you test, `content gettype` is a free reachability probe
that costs nothing and never triggers a permission error.

---

### 10. What actually is `call()` and why does everyone say it is dangerous?

`call()` is a generic remote procedure call bolted onto the provider interface. You pass a method
name string, an argument string and an arbitrary `Bundle`, and get an arbitrary `Bundle` back. There
is no schema, no type checking, and no automatic permission enforcement.

It is dangerous for three compounding reasons. It appears nowhere in the manifest, so a reviewer
reading configuration cannot see it exists. It gets no per-URI permission check, so on a provider with
no declared permission it is completely open. And developers reach for it precisely when they want to
do something that does not fit the query/insert/update/delete shape — which in practice means
privileged internal operations like fetching a token, toggling debug mode, or executing raw SQL.

---

### 11. How do I find `call()` method names if they are not written down anywhere?

Four techniques, in order of reliability:

1. **Read the switch statement in JADX.** `grep -rn -A40 "public Bundle call" out/sources/`.
2. **Pull the strings from the DEX.** The method names are string constants compared at runtime, so
   they survive normal obfuscation.
3. **Hook `ContentProvider.call` with Frida and use the app.** The app's own components call these
   methods; you will see them go past.
4. **Brute force with a wordlist**, using the difference between "returned null" and "returned a
   Bundle or threw" as your oracle. The script `scripts/provider-call-fuzz.py` in this chapter does
   this.

---

### 12. What is a "confused deputy" and how does it apply to URI grants?

A confused deputy is a privileged component that gets tricked into using its privileges for someone
else. It is not compromised — it does exactly what it was built to do, just for the wrong person.

With URI grants, the deputy is an app that (a) can read a privileged provider and (b) has an exported
component that starts an intent supplied by the caller and hands the result back. The attacker crafts
an inner intent aimed at the privileged provider with `FLAG_GRANT_READ_URI_PERMISSION` set, wraps it
in an extra, and calls the deputy. The deputy runs it with the deputy's identity, gets a grantable URI
back, and passes it to the attacker — and `ActivityManagerService` dutifully records a grant in the
attacker's favour.

The fix belongs in the deputy, not in the provider. The provider behaved correctly throughout.

---

### 13. Is `android:exported="false"` enough on its own?

For cross-UID access, yes — with three caveats.

First, `android:sharedUserId`. If the app shares a UID with another app, that app runs as the same UID
and the framework grants access unconditionally, `exported` notwithstanding.

Second, the merged manifest. Your source manifest may say `false` while a library's merged entry says
`true` for a different provider you did not know existed.

Third, other reachability paths. A non-exported provider is still reachable from a WebView inside the
app if `setAllowContentAccess(true)` and the WebView loads attacker-controlled content, and from any
code-execution primitive inside the app's own process.

---

### 14. Why is `<root-path path="." />` in `file_paths.xml` such a big deal?

Because it tells `FileProvider` that the entire filesystem is a shareable root. `FileProvider` will
then produce a valid `content://` URI for any file the app's UID can read — including
`/data/data/<pkg>/shared_prefs/auth.xml` and `/data/data/<pkg>/databases/app.db`.

By itself, that is only exploitable if the provider is exported, or if an attacker can influence which
file the app chooses to share. But both of those are common, and the check costs one grep. It appears
constantly because it is the top Stack Overflow answer to "FileProvider says my file is outside the
configured paths".

---

### 15. Is `android:pathPattern="/files/*"` a wildcard?

No, and this is the trap. Android's `pathPattern` uses a simplified glob in which `*` means "zero or
more repetitions of the *preceding character*", not "anything". So `/files/*` means "the string
`/file`, then zero or more `s` characters, then `/`".

To match "anything under `/files/`" you need `/files/.*`, where `.` means "any character" and `*`
repeats it.

Developers get this wrong in both directions. When the rule ends up narrower than intended, the app
breaks and someone fixes it. When it ends up wider than intended, nothing breaks and nobody notices.
Check every `pathPattern` by hand.

---

### 16. My provider crashed the target app and then my own tool died. Why?

You acquired the provider with `acquireContentProviderClient()` — the *stable* variant — which tells
the framework "I cannot function without this provider". When the provider's process dies, the
framework kills yours too, on the theory that you are now broken.

Use `acquireUnstableContentProviderClient()` when fuzzing. Your calls will throw
`DeadObjectException` instead of taking you down with the target. `adb shell content` already handles
this for you.

---

### 17. Why does touching a provider start the whole app?

Because resolving a `content://` authority requires the provider object to exist, and the provider
object lives inside the owning app's process. `ActivityManagerService` will fork and start that
process, run `Application`'s constructor, call `installContentProviders()` (which calls your
`ContentProvider.onCreate()`), then `Application.onCreate()`, and only then serve your query.

This is a genuinely useful primitive. An app with no exported activity, service or receiver can still
be forced to run by anyone who knows one of its provider authorities. It is also why library
initialisers (WorkManager, Firebase) piggyback on stub providers — declaring a provider is the only
supported way to run code before `Application.onCreate()`.

---

### 18. On which thread does `query()` run?

On a Binder thread-pool thread, not the main thread. `onCreate()` is the exception — that runs on the
main thread during app startup.

Two consequences. Blocking I/O in `query()` is fine from the framework's perspective (though it blocks
the *caller*). And multiple calls can run concurrently, so any mutable state the provider keeps in an
instance field is a race condition an attacker can drive. That is a real, if less common, vulnerability
class worth probing with concurrent requests.

---

### 19. I dumped the `.db` file through a traversal but the interesting row is missing. Where is it?

Almost certainly in the write-ahead log. SQLite in WAL mode appends new and modified pages to a
`<name>.db-wal` file and does not necessarily checkpoint them into the main database. A row inserted
five minutes ago may exist only in the WAL, and a row *deleted* five minutes ago may still be fully
present there.

Always pull all three files together: `app.db`, `app.db-wal`, `app.db-shm` (or `app.db-journal` in
rollback-journal mode). Then open the `.db` with the WAL alongside it so SQLite replays it.

---

### 20. Drozer says the provider is not vulnerable. Am I done?

No. Drozer's `scanner.provider.injection` tests selection and projection but not sort order. Neither
Drozer nor any other common scanner enumerates `call()` methods. `scanner.provider.traversal` uses a
fixed payload list that does not include double encoding or absolute paths. And every scanner is blind
to a route whose path it never guessed.

Scanners are a first pass. The findings that matter are usually the ones you get by reading the
provider's code in JADX and then aiming a specific request at a specific route.

---

### 21. How do I explain to a developer why "the authority is obscure" is not a defence?

Show them, in ten seconds:

```bash
adb shell dumpsys package providers | grep -i theirpackage
```

Every provider on the device, with its authority, is printed by a command any developer can run and
any app can approximate through `PackageManager`. There is no obscurity. The authority is a routing
key, not a secret, and it is published in the manifest, which is part of the APK anyone can download.

---

### 22. What is the single most valuable thing to check first?

Run this and read the output:

```bash
adb shell dumpsys package <pkg> | grep -A12 "Provider{"
```

If any provider shows `exported=true` with no permission, or with a permission whose
`protectionLevel` is `normal`, you have a finding before you have written a single payload. Everything
else in the chapter is for the cases where that first check comes back clean.
