# Lab 04 — Provider Surgery

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 02](lab-02-full-audit.md), [Lab 03](lab-03-proving-reachability.md),
[Chapter 32 §`<provider>`](../README.md), [27-ContentProviders](../../27-ContentProviders/README.md)

---

## Objective

Audit `<provider>` declarations at the level of detail they actually require: authorities, the three
overlapping permission attributes, `grantUriPermissions`, `<grant-uri-permission>` paths, and
`<path-permission>` — the element the chapter calls subtle and which is misused more often than any
other.

Then prove, for each provider, exactly which URIs an unprivileged app can reach.

## Why this matters

Providers carry more security-relevant manifest surface than any other component, and the attributes
interact in ways that are genuinely easy to get wrong:

- `android:permission` is overridden by `readPermission` and `writePermission` **independently**, so a
  provider can be write-protected and read-open
- `<path-permission>` can **widen** access, not just narrow it
- Paths not covered by a `<path-permission>` fall back to the provider-level permission — the opposite
  of what most people assume
- `grantUriPermissions="true"` makes the provider a target for URI-grant theft via intent redirection,
  even when it is otherwise well guarded

An auditor who reads `android:exported="false"` and moves on will miss all of it.

---

## Setup

Use [`examples/vulnerable-manifest.xml`](../examples/vulnerable-manifest.xml) from this chapter, which
has planted provider issues, plus a real app of your choosing.

```bash
# host
export PKG=com.example.target
adb pull $(adb shell pm path $PKG | head -1 | sed 's/package://') target.apk
apktool d -f target.apk -o work/ >/dev/null
```

Do **not** read the answer key ([`examples/vulnerable-manifest-ANSWERS.md`](../examples/vulnerable-manifest-ANSWERS.md))
until Step 9.

---

## Steps

### Step 1 — Enumerate every provider

```bash
# host
grep -A15 '<provider' work/AndroidManifest.xml
```

```bash
# device — what the platform actually parsed
adb shell dumpsys package $PKG | grep -E 'authority=|readPermission=|writePermission=|grantUriPermissions='
```

For each provider, fill in this table. Leave a cell blank if the attribute is absent — **absence is
information**.

| # | Class | `authorities` | `exported` | `permission` | `readPermission` | `writePermission` | `grantUriPermissions` |
|---|---|---|---|---|---|---|---|
| 1 | | | | | | | |

**Q1.** How many providers are declared? How many are exported?

**Q2.** For each, what is the *effective* read permission and the *effective* write permission? State
the precedence rule you applied.

### Step 2 — Resolve the permission precedence

This is the part people get wrong, so work it out explicitly rather than from memory.

**Q3.** For a provider with `android:permission="P"` and `android:readPermission="R"` (no
`writePermission`), what permission does a caller need to **read**? To **write**?

**Q4.** For a provider with only `android:permission="P"`, what does a caller need for each?

**Q5.** Is there a combination in your target that leaves reads unguarded while writes are protected,
or vice versa? That asymmetry is frequently unintentional.

### Step 3 — Audit `<grant-uri-permission>`

```bash
# host
grep -B5 -A10 'grant-uri-permission' work/AndroidManifest.xml
```

**Q6.** Which providers declare `grantUriPermissions="true"`? For each, what do the child
`<grant-uri-permission>` elements allow?

| Attribute | Meaning |
|---|---|
| `android:path` | Exact match |
| `android:pathPrefix` | Prefix match |
| `android:pathPattern` | Glob-style pattern |

**Q7.** Any provider with `grantUriPermissions="true"` and **no** child elements? What does that mean?
(Read the element documentation carefully before answering — this one is counter-intuitive.)

**Q8.** Any `<grant-uri-permission android:path="/" />` or a `pathPrefix` of `/`? What is the scope of
what can be granted?

### Step 4 — Audit `<path-permission>`

```bash
# host
grep -B8 -A8 'path-permission' work/AndroidManifest.xml
```

For each `<path-permission>` record: the path spec, and the `permission` / `readPermission` /
`writePermission` it applies.

**Q9.** For each, is the permission it applies **stronger or weaker** than the provider-level
permission?

**Q10.** If it is weaker, what have you found? Write the consequence in one sentence.

**Q11.** What guards a path that is **not** matched by any `<path-permission>`? Trace it through the
precedence rules and state the answer explicitly.

### Step 5 — Audit FileProvider `<paths>`

```bash
# host
find work/res/xml -name '*.xml' | xargs grep -l 'paths' 2>/dev/null
cat work/res/xml/file_paths.xml 2>/dev/null
```

Compare against [`examples/file_paths_insecure.xml`](../examples/file_paths_insecure.xml) and
[`examples/file_paths_secure.xml`](../examples/file_paths_secure.xml).

**Q12.** Which path elements are declared? Map each to the directory it exposes:

| Element | Directory |
|---|---|
| `<files-path>` | `getFilesDir()` |
| `<cache-path>` | `getCacheDir()` |
| `<external-path>` | external storage root |
| `<external-files-path>` | `getExternalFilesDir()` |
| `<external-cache-path>` | `getExternalCacheDir()` |
| `<root-path>` | **the filesystem root** |

**Q13.** Is `<root-path>` present? With `path="."`? What is the resulting exposure, and what would you
rate it?

### Step 6 — Test from the shell

```bash
# adb shell
content query --uri content://<authority>/
content query --uri content://<authority>/<path>
content read  --uri content://<authority>/<path>/file
content call  --uri content://<authority> --method <name>
```

Work through each authority and each path you found.

**Q14.** Which URIs return data from the shell? Record them.

### Step 7 — **Prove it from an unprivileged app**

Everything in Step 6 ran as UID 2000. Now prove real reachability.

Extend the probe app from [Lab 03](lab-03-proving-reachability.md) with a provider matrix:

```java
private static final String[] URIS = {
    "content://com.example.target.provider/users",
    "content://com.example.target.provider/files/config.xml",
    "content://com.example.target.fileprovider/root/data/data/com.example.target/databases/app.db",
    // ...every URI you found
};

private void probeProviders() {
    for (String u : URIS) {
        // READ
        try (Cursor c = getContentResolver().query(Uri.parse(u), null, null, null, null)) {
            Log.i(TAG, "READ  " + u + " -> " +
                  (c == null ? "null cursor" : c.getCount() + " rows"));
        } catch (SecurityException e) {
            Log.i(TAG, "READ  " + u + " -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, "READ  " + u + " -> ERROR: " + e);
        }

        // OPEN FILE — a separate permission path from query()
        try (java.io.InputStream in =
                 getContentResolver().openInputStream(Uri.parse(u))) {
            Log.i(TAG, "OPEN  " + u + " -> READABLE");
        } catch (SecurityException e) {
            Log.i(TAG, "OPEN  " + u + " -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, "OPEN  " + u + " -> " + e.getClass().getSimpleName());
        }

        // WRITE — tests the write permission independently
        try {
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put("probe", "x");
            Uri r = getContentResolver().insert(Uri.parse(u), cv);
            Log.i(TAG, "WRITE " + u + " -> ACCEPTED (" + r + ")");
        } catch (SecurityException e) {
            Log.i(TAG, "WRITE " + u + " -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, "WRITE " + u + " -> " + e.getClass().getSimpleName());
        }
    }
}
```

> **⚠️ Warning**
> The `insert` probe **writes to the target app's data**. On an app you do not own, or on production
> data, do not run it — or snapshot the data directory first. Read-only probing is sufficient to
> establish most findings.

**Q15.** Build the reachability matrix:

| URI | Shell read | App read | App openFile | App write |
|---|---|---|---|---|
| | | | | |

**Q16.** How many URIs were readable from the shell but denied to the app? Those would have been false
positives.

**Q17.** Any URI where `query()` is denied but `openInputStream()` succeeds? Explain why that can
happen — it is a real and frequently-missed asymmetry.

### Step 8 — Automate

```bash
# host
python3 ../scripts/manifest-audit.py ../../32-Manifest/examples/vulnerable-manifest.xml
python3 ../scripts/manifest-audit.py work/AndroidManifest.xml --target-sdk <the app's targetSdk>
```

**Q18.** Does the script find every provider issue you found by hand? Anything it missed, or flagged
that you judged benign?

### Step 9 — Check the answer key

Now open [`examples/vulnerable-manifest-ANSWERS.md`](../examples/vulnerable-manifest-ANSWERS.md).

**Q19.** Which planted provider issues did you miss? For each, what would have led you to it?

### Step 10 — Write the findings

For each confirmed issue:

- The exact declaration, quoted from the manifest
- The precedence reasoning that makes it a problem
- The URI and the probe-app evidence
- What an attacker retrieves or modifies
- Severity, with the prerequisite stated
- The corrected declaration

**Q20.** For the FileProvider issue (if present), write the fix as a corrected `<paths>` file, not
just prose.

---

## Hints

<details>
<summary>Hint 1 — the permission precedence rule</summary>

`readPermission` and `writePermission` each **override** `permission` for their respective operation,
independently. So:

- `permission="P"` alone → `P` needed for both read and write
- `permission="P"` + `readPermission="R"` → `R` for read, `P` for write
- `readPermission="R"` alone → `R` for read, **nothing** for write

That last case is the one that catches people.
</details>

<details>
<summary>Hint 2 — grantUriPermissions with no children</summary>

Read the element documentation. `grantUriPermissions="true"` on the `<provider>` with no child
elements means grants may be issued for **any** URI in the provider. The child
`<grant-uri-permission>` elements are used when the attribute is `false` to carve out specific
grantable subsets — so children *restrict*, they do not enable.
</details>

<details>
<summary>Hint 3 — query denied but openInputStream works</summary>

`query()` and `openFile()` go through different code paths in `ContentProvider`, and a provider can
implement permission checks in one and not the other. `<path-permission>` also applies differently.
`FileProvider` in particular serves files through `openFile` and does not implement a meaningful
`query`, so the two behave quite differently by design.
</details>

<details>
<summary>Hint 4 — everything is denied and I cannot tell if I am testing correctly</summary>

Sanity-check your probe against a provider you know is world-readable:

```java
getContentResolver().query(
    android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
    null, null, null, null);
```

If that also fails, the probe is broken rather than the target being secure. Check the `<queries>`
declaration and that the app has the storage permission if needed.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q3–Q4.** With `permission="P"` and `readPermission="R"`: reads need `R`, writes need `P`.
`readPermission` and `writePermission` override `permission` independently for their operation. With
only `permission="P"`, both operations need `P`.

**Q5.** The dangerous asymmetry is `writePermission` set with no `readPermission` and no
`permission` — writes are guarded, reads are wide open. Developers add `writePermission` thinking
"protect the data from modification" and leave reads entirely unprotected.

**Q7.** `grantUriPermissions="true"` with no children permits grants for **any** URI in the provider.
The children exist to carve out grantable subsets when the attribute is `false`. So "no children" is
the *broadest* configuration, not the narrowest — the opposite of the intuitive reading.

**Q9–Q11.** A `<path-permission>` applying a weaker permission than the provider level **widens**
access for that path — a real finding, and the reason the chapter calls the element subtle. A path
matched by no `<path-permission>` falls back to the provider-level permission; it is not implicitly
denied. Auditors who assume "unlisted means blocked" have it backwards.

**Q13.** `<root-path name="root" path="." />` maps the FileProvider onto the filesystem root, so any
file the app's UID can read becomes shareable by URI. Combined with an intent-redirection bug it
becomes arbitrary file disclosure from the sandbox. Typically **High**, and there is almost never a
legitimate reason for it.

**Q16.** Expect several. `shell` (UID 2000) holds privileges an app does not, so provider URIs
readable from `adb shell` are frequently denied to an ordinary app. Every one of those would have been
a false positive in a report.

**Q17.** `query()` and `openFile()` are separate methods with separate permission handling, and a
provider may guard one and not the other. `FileProvider` is the clearest case: it serves content
through `openFile` and has no meaningful `query` implementation, so testing only `query` tells you
almost nothing about a FileProvider's exposure.

</details>

---

## Success criteria

- [ ] You enumerated every provider with all seven security-relevant attributes
- [ ] You resolved the read/write permission precedence explicitly rather than from memory
- [ ] You identified any asymmetry between read and write protection
- [ ] You correctly interpreted `grantUriPermissions="true"` with no child elements
- [ ] You determined whether each `<path-permission>` narrows or **widens** access
- [ ] You stated what guards a path matched by no `<path-permission>`
- [ ] You mapped every FileProvider `<paths>` element to the directory it exposes
- [ ] You tested `query`, `openInputStream` **and** `insert` separately from an unprivileged app
- [ ] You produced the reachability matrix and counted the shell-only false positives
- [ ] You can explain why `query` may be denied while `openInputStream` succeeds
- [ ] Every finding quotes the declaration, shows probe-app evidence, and includes a corrected version
