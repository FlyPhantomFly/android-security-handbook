# Lab 04 — Sandbox Escape by the Front Door: Exported Components

**Difficulty:** Intermediate
**Time:** 2 hours
**Prerequisites:** [Lab 03](lab-03-attacker-app.md),
[Chapter 21 §3.14.3](../README.md#3143-ipc-you-voluntarily-exposed) and
[§5.7](../README.md#57-vulnerability-class--contentprovideropenfile-path-traversal-an-fd-leak),
a working probe APK.

---

## Objective

Take a target application whose sandbox is intact, find an exported `ContentProvider` with an
`openFile()` implementation, exploit a path traversal through it to read a file the provider never
intended to share, then remediate with `FileProvider` and verify the fix from the same probe APK.

The point is not the traversal technique. The point is that **the sandbox held throughout**, and the
data left anyway, because the developer opened a door in it.

## Why this matters

> **🧠 Mental Model**
> The sandbox is a wall. Exported components are doors the developer cut into it deliberately, because
> an app that cannot talk to anything is not useful. The wall does not have an opinion about the doors.
> Every question you can ask about a door — who may open it, what is behind it, does it check who is
> knocking — is an application question, not a platform question.

This lab exists because the highest-yield findings on an ordinary Android engagement are here, and
because the mechanism behind the most serious one — file-descriptor passing — is genuinely
counter-intuitive the first time you meet it. An attacker who cannot open a file gets its contents,
because a more privileged process opened it on their behalf and handed over a descriptor that the
kernel will never recheck.

> **📖 Definition — exported component**
> An `<activity>`, `<service>`, `<receiver>` or `<provider>` that other applications may invoke. It is
> exported if `android:exported="true"`, or — for apps targeting API < 31 — implicitly if it declares an
> `<intent-filter>` and does not say otherwise. `<provider>` defaulted to `exported="true"` for apps
> targeting below API 17, which is why very old apps are so consistently leaky.

---

## Scope and cross-references

This lab covers exported components **only as a boundary question**: what the sandbox does and does not
do about them. It deliberately does not re-teach IPC mechanics or manifest analysis. Those live in
their own chapters and are better there:

| For | Read |
|---|---|
| How Binder actually carries a call, `getCallingUid`, transaction codes | [25-Binder](../../25-Binder/README.md) |
| The full IPC attack surface and the probe-app methodology | [24-IPC](../../24-IPC/README.md), and its [attacker-app](../../24-IPC/examples/attacker-app/README.md) |
| Intent redirection, `PendingIntent` mutability, deep links | [26-Intent](../../26-Intent/README.md) |
| `UriMatcher`, URI permission grants, provider SQL injection | [27-ContentProviders](../../27-ContentProviders/README.md) |
| Every manifest attribute that affects exposure, and how to read a binary manifest | [32-Manifest](../../32-Manifest/README.md) |

What is *here* and nowhere else: the argument that none of this is a sandbox failure, and the
descriptor-passing mechanism that makes `openFile` the highest-severity case.

---

## Setup

Use the victim from [Lab 03](lab-03-attacker-app.md) — it already has the vulnerable provider — or any
app you own with an exported provider. Install both apps.

```bash
# host
adb install -r victim/build/outputs/apk/debug/victim-debug.apk
adb install -r attacker/build/outputs/apk/debug/attacker-debug.apk
adb shell am start -n com.example.victim/.MainActivity     # let it write its prefs
```

Confirm the target's identity and that it is intact:

```bash
# adb shell
pm list packages -U | grep victim
ls -ld /data/data/com.example.victim   2>&1     # Permission denied — the wall is standing
```

---

## Steps

### Step 1 — Enumerate the doors, statically

```bash
# host
apktool d -f victim.apk -o work/ >/dev/null
grep -nE '<(activity|activity-alias|service|receiver|provider)' work/AndroidManifest.xml
```

Build the inventory. For every component record four things, because the fourth is the one people
forget:

| Component | Type | `exported` | Permission attribute | `targetSdk` of the app |
|---|---|---|---|---|

```bash
# host
grep -oE 'android:targetSdkVersion="[0-9]+"' work/apktool.yml work/AndroidManifest.xml
grep -oE 'android:(permission|readPermission|writePermission|protectionLevel)="[^"]*"' work/AndroidManifest.xml
grep -oE 'android:authorities="[^"]*"' work/AndroidManifest.xml
grep -oE 'android:grantUriPermissions="[^"]*"' work/AndroidManifest.xml
```

**Question 1.** One component in your inventory has no `android:exported` attribute at all but does have
an `<intent-filter>`. Is it exported? What do you need to know before you can answer, and where do you
find it?

**Question 2.** Another has `android:permission="com.example.victim.permission.INTERNAL"`. Before you
record it as protected, what must you check about that permission, and which file tells you?

### Step 2 — Confirm the platform's own view

Static analysis of a manifest is a claim. `dumpsys` is the platform's own record, and it accounts for
manifest merging from libraries and SDKs, which the source manifest does not.

```bash
# adb shell
dumpsys package com.example.victim | sed -n '/Activity Resolver Table/,/Permissions:/p'
dumpsys package com.example.victim | grep -A3 -i 'ContentProvider Authorities'
dumpsys package com.example.victim | grep -iE 'permission|protectionLevel'
```

**Question 3.** Is any component in the platform's list absent from the source manifest you decoded, or
outside the app's own package prefix? What does that mean, and why is it a common blind spot?

### Step 3 — Probe from the shell (and understand why that is not enough)

```bash
# adb shell
content query --uri content://com.example.victim.provider
content read  --uri content://com.example.victim.provider/input.txt
```

Record the results — and then immediately record that they prove nothing about apps. Your shell is UID
2000 in the `shell` domain and holds privileges no application holds.

**Question 4.** Name a concrete case in which `content query` from the shell would succeed and the same
query from an installed app would fail. Name one where the reverse could happen.

### Step 4 — Probe from the app, which is the real experiment

Run the probe APK from Lab 03 and read section 3.

```bash
# host
adb logcat -c
adb shell am start -n com.attacker.sandboxprobe/.ProbeActivity
adb logcat -s SANDBOXPROBE:W
```

You should see `REACHABLE` on the plain `query()`. Fill in both columns:

| Operation | From `adb shell` | From the probe APK |
|---|---|---|
| `query()` on the authority root | | |
| `openFile()` on a legitimate name | | |
| `insert()` | | |
| `call()` | | |

**Question 5.** `query()` returned the session token to an app holding no permissions at all. Walk the
access decision: which check did the platform perform, what did it consult, and what did it conclude?
Was any part of the sandbox bypassed?

### Step 5 — The traversal

The provider's `openFile()` concatenates a caller-supplied path segment onto `filesDir` and calls
`ParcelFileDescriptor.open()`. Attack it.

```kotlin
// in the probe
listOf(
    "input.txt",                                             // control: should work
    "../shared_prefs/secure.xml",                            // one level up
    "../databases/app.db",
    "../../../../data/data/com.example.victim/shared_prefs/secure.xml",
    "..%2Fshared_prefs%2Fsecure.xml",                        // encoded
    "../../../../system/etc/hosts"                           // outside the app entirely
).forEach { seg -> /* openInputStream(Uri.withAppendedPath(base, seg)) */ }
```

> **⚠️ Warning**
> `Uri.withAppendedPath` and `Uri.parse` normalise some inputs. If a payload silently does nothing, log
> `uri.lastPathSegment` and `uri.path` **inside the victim** to see exactly what arrived. Half the time
> a "failed" traversal never left the attacker.

Record which payloads work.

**Question 6.** The attacker's own `File("/data/data/com.example.victim/shared_prefs/secure.xml").canRead()`
returned `false` in section 1 of the probe. The traversal returned the file's contents. Both are true
simultaneously. Explain the mechanism precisely — which process called `open()`, under which identity,
and at what moment did the kernel perform its permission check?

**Question 7.** `../../../../system/etc/hosts` probably succeeded and another app's private data
certainly did not. State the exact bound on this vulnerability, and write the one-sentence severity
statement you would put in a report — including the prerequisite an attacker needs.

### Step 6 — Establish reach-through

A door is only as serious as the room behind it. Do the part no tool does for you.

For each `REACHABLE` result, answer: what can you make this component do that you could not do
directly?

| Reached | Contents | Reach-through |
|---|---|---|
| `shared_prefs/secure.xml` | session token | Authenticate to the backend as the user? Test it. |
| `databases/app.db` | | |
| `files/` contents | | |

**Question 8.** You have the session token. Before you write "account takeover", what must you actually
verify, and how? What would make the same token a **Low** finding rather than a **High** one?

### Step 7 — Remediate, two ways

**Preferred: delete the provider and use `FileProvider`.**

```xml
<!-- victim: AndroidManifest.xml -->
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.victim.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/provider_paths" />
</provider>
```

```xml
<!-- victim: res/xml/provider_paths.xml — an allowlist, not a filter -->
<paths>
    <files-path name="exports" path="exports/" />
</paths>
```

```kotlin
// Sharing is now a per-URI, per-recipient, revocable grant — not a standing door.
val file = File(File(filesDir, "exports").apply { mkdirs() }, "report.pdf")
val uri  = FileProvider.getUriForFile(this, "com.example.victim.fileprovider", file)
startActivity(Intent(Intent.ACTION_SEND).apply {
    type = "application/pdf"
    putExtra(Intent.EXTRA_STREAM, uri)
    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
})
```

**If a custom provider genuinely must remain**, canonicalise and verify containment:

```kotlin
override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
    if (mode != "r") throw SecurityException("read-only")
    val root   = File(context!!.filesDir, "exports").canonicalFile
    val name   = uri.lastPathSegment ?: throw FileNotFoundException("no segment")
    val target = File(root, name).canonicalFile
    // canonicalFile resolves ".." and symlinks. Compare AFTER resolution, and
    // include the separator so /exports-evil does not match /exports.
    if (!target.path.startsWith(root.path + File.separator))
        throw SecurityException("path escapes the export root")
    return ParcelFileDescriptor.open(target, ParcelFileDescriptor.MODE_READ_ONLY)
}
```

> **🔍 Pentester's Note**
> When you review a fix, check the comparison happens **after** canonicalisation and that the separator
> is included. `startsWith(root.path)` without the trailing separator is a real bug: `/data/.../exports`
> is a prefix of `/data/.../exports-backup`. And a check performed on the *raw* string before resolving
> `..` is no check at all. These two mistakes account for most "fixed" traversals that are not fixed.

Now re-run the probe.

**Question 9.** Which rows changed, and which did not? If `query()` still returns the token, what did
you forget?

### Step 8 — The honest write-up

**Question 10.** Write the finding. It must contain, in this order: the vulnerable code, why a developer
writes it, how you detect it statically and dynamically, the exploit, the fix as code, and a severity
with its prerequisite stated. Then add one sentence stating which sandbox mechanism failed.

---

## Hints

<details>
<summary>Hint 1 — deciding whether a component is exported without an explicit attribute</summary>

The rule depends on the app's `targetSdkVersion`:

- Any component with an `<intent-filter>` and no explicit `android:exported` is **exported** for apps
  targeting below API 31.
- From API 31, a component with an `<intent-filter>` **must** declare `android:exported` explicitly or
  installation fails — so on a modern target the attribute is always there.
- `<provider>` specifically defaulted to `exported="true"` for apps targeting below API 17.

So the first thing you read in any manifest is `targetSdkVersion`, and `dumpsys package` settles any
remaining doubt because it reports what the platform actually decided.
</details>

<details>
<summary>Hint 2 — a permission attribute that protects nothing</summary>

A custom permission is only as strong as its `protectionLevel`. Check the `<permission>` declaration:

```bash
# host
grep -A3 '<permission ' work/AndroidManifest.xml
```

`protectionLevel="normal"` is granted silently at install to any app that asks for it, so it provides
**no protection at all** against a malicious app — it only stops accidental use. `signature` is a real
control. `dangerous` requires a user prompt, which raises cost but does not prevent it.

Also check for the classic race: if a *different* app declares the same permission name first, and the
victim's declaration loses, the protection can end up defined by an attacker-controlled app.
</details>

<details>
<summary>Hint 3 — <code>content read</code> exists and you did not know</summary>

```bash
# adb shell
content query --uri content://authority/path
content read  --uri content://authority/path
content insert --uri content://authority/path --bind key:s:value
content call  --uri content://authority --method someMethod
```

Useful for fast triage. Remember the whole point of this lab: `content` runs as UID 2000. Confirm every
result from the probe APK before it becomes a finding.
</details>

<details>
<summary>Hint 4 — the traversal payload disappears</summary>

`Uri` normalisation. Try, in order: building the URI from a full string rather than
`withAppendedPath`; URL-encoding the separators (`..%2F`); using multiple path segments so
`lastPathSegment` returns only the final one (which tells you the provider's parsing is different from
what you assumed); and logging what actually arrives on the victim's side.

If the provider uses `uri.path` rather than `uri.lastPathSegment`, your payload shape changes
completely. Read the decompiled `openFile` before guessing.
</details>

<details>
<summary>Hint 5 — you cannot tell whether the fix works</summary>

Test three inputs against the fixed provider, not one: a legitimate name (must succeed), a traversal
(must be refused), and a *symlink* you plant inside the export directory pointing outside it (must be
refused, because `canonicalFile` resolves symlinks too). The third is the one that distinguishes a real
fix from a string check.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** You cannot answer without the app's `targetSdkVersion`. Below API 31, a component with an
`<intent-filter>` and no explicit `android:exported` is exported. From API 31 the attribute is mandatory
in that situation, so it will be present. `apktool.yml` carries the SDK versions, and `dumpsys package`
gives you the platform's actual decision, which is the authority.

**2.** Its `protectionLevel`, declared in the `<permission>` element of whichever app defines it. A
`normal` permission is granted silently at install to any app that requests it and therefore protects
nothing against a malicious app. Only `signature` (or `signatureOrSystem`) is a genuine control against
an unrelated attacker. Recording a component as "protected" because it has a `permission` attribute,
without checking the level, is a common false negative.

**3.** Components contributed by libraries and SDKs through manifest merging. They appear in
`dumpsys package` and in the APK's real manifest but not in the app's `src/main` manifest, and their
package names sit outside the app's own prefix. They run with the app's full identity. This is a common
blind spot precisely because a reviewer reading the app's own source never sees them — which is why
§11.3 says to enumerate the *merged* component list and flag anything outside the app's package prefix.

**4.** Shell succeeds, app fails: the provider is protected by a `signature` permission that the shell's
platform-adjacent privileges or a `signatureOrSystem` grant let it past, or by an SELinux rule that
permits `shell` but not `untrusted_app`, or the provider explicitly allowlists UID 2000 via
`Binder.getCallingUid()`.

The reverse — app succeeds, shell fails — is rarer but real: a provider that checks
`getCallingPackage()` against an allowlist, or requires a permission the shell does not hold, or grants
access only via a URI permission grant the app obtained through a normal Intent flow. It is also what
happens when *your shell command* is malformed and the app's code path is not; do not mistake your own
syntax error for a control.

Run both. Record both. The disagreement is always informative.

**5.** The platform performed a component-visibility and permission check when the attacker's
`ContentResolver.query()` reached `ActivityManagerService`/`ContentProviderHelper`. It consulted the
provider's manifest declaration: `exported="true"`, no `readPermission`, no `permission`,
no `android:permission` on the `<provider>`. It concluded, correctly, that any caller is allowed.

No part of the sandbox was bypassed. DAC was never asked, because the attacker never touched the
victim's files — the *victim* read its own preferences, in its own process, as its own UID, and handed
the result back over Binder. SELinux permitted the Binder transaction because `untrusted_app` may talk
to `untrusted_app` over Binder, which it must, or no app could ever talk to any other. The sandbox did
exactly what it was configured to do.

**6.** The **victim's** process called `ParcelFileDescriptor.open()`, running as the victim's UID in the
victim's SELinux context. The kernel performed both its DAC check and its SELinux check *at that
moment*, against *that* process's credentials, and both passed — correctly, because an app may read its
own files.

The kernel then created an open file description and the framework transferred the descriptor back to
the attacker inside the Binder reply (ultimately via `SCM_RIGHTS` on the underlying transport). Reads
through a descriptor are **not** rechecked: the permission check happens once, at `open()`, in the
opening process. The attacker therefore holds access that was already granted to someone else.

This is why this bug class is so much more serious than a `query()` leak. A `query()` gives you what the
developer chose to return. `openFile()` with a traversal gives you the target app's entire read
authority.

**7.** The bound is exactly the victim's own read authority: anything the victim's UID and SELinux
context can read. `/system/etc/hosts` is world-readable and `untrusted_app` may read `system_file`, so
it succeeds. Another app's private data fails, because the victim cannot read that either.

Severity sentence: *"An application installed by the user, holding no permissions, can read any file
readable by the target application — including its credential store — by supplying a relative path to
the target's exported `ContentProvider`. Prerequisite: the attacker's app must be installed and must
declare the target's authority in `<queries>`; no user interaction and no elevated privilege is
required."*

That is High, and the reason it is High is the credential store, not the traversal.

**8.** Verify that the token is actually accepted by the backend, from a different device or IP, and
that it grants something meaningful. Take it, present it to the API, and record the response. Without
that, "account takeover" is speculation.

It drops to Low if the token turns out to be short-lived, single-use, bound to the device (through
attestation, a device ID, or a channel-bound key), scoped to a trivial capability, or already expired by
the time you use it. Those are exactly the properties you should be reporting about a credential —
lifetime, binding, revocability, blast radius — rather than the mere fact that it was stored somewhere.

**9.** The `openFile` rows change to `DENIED` or `ABSENT`. The `query()` row **does not**, if you only
replaced `openFile` and left the provider exported. `FileProvider` replaces the file-serving path; it
does not remove a separate `query()` that hands out the token.

If `query()` still returns data after remediation, the fix was incomplete: the provider must be
`android:exported="false"`, and any legitimate cross-app sharing must go through per-URI grants
(`FLAG_GRANT_READ_URI_PERMISSION`) rather than a standing open authority.

**10.** A complete finding looks roughly like:

> **Vulnerable code.** `LeakyProvider.openFile()` builds `File(context.filesDir, uri.lastPathSegment)`
> and opens it, with no canonicalisation and no containment check, in a provider declared
> `android:exported="true"` with no permission attribute.
>
> **Why developers write it.** It is the shortest code that satisfies "let another app open a file we
> produced". The `FileProvider` route requires a `<paths>` resource, per-URI grants, and changes at
> every call site; hand-rolling `openFile` works immediately in testing, where every caller is your own
> app supplying a well-formed name.
>
> **Detection — static.** `grep -rn 'openFile' out/sources/` and check whether any caller-controlled
> component of the URI reaches a `File` constructor without `getCanonicalPath()` and a prefix check.
> Cross-check `android:exported` and any permission attribute on the `<provider>`, and the app's
> `targetSdkVersion`.
>
> **Detection — dynamic.** From an installed probe application declaring the authority in `<queries>`,
> call `contentResolver.openInputStream()` with `../` segments and observe whether content is returned.
> Confirm from the app, not from `adb shell`.
>
> **Exploit.** `content://com.example.victim.provider/../shared_prefs/secure.xml` returns the
> application's stored session token to an application holding no permissions.
>
> **Fix.** Replace with `androidx.core.content.FileProvider` and a `<paths>` allowlist, set the custom
> provider `android:exported="false"`, and share individual files with
> `FLAG_GRANT_READ_URI_PERMISSION`. If a custom provider must remain, canonicalise and verify
> containment *after* resolution, including the path separator in the prefix comparison.
>
> **Severity.** High. Prerequisite: an attacker-controlled application installed on the device, no user
> interaction, no elevated privilege, no permission beyond package visibility of the target.
>
> **Which sandbox mechanism failed.** None. The application sandbox operated correctly throughout; the
> data was disclosed through an interface the application deliberately exposed, and via a file
> descriptor that the target application opened with its own authority.

</details>

---

## Success criteria

- [ ] You produced a component inventory including `exported`, permission, protection level, and the
      app's `targetSdkVersion`
- [ ] You cross-checked the source manifest against `dumpsys package` and looked for SDK-contributed
      components
- [ ] You can state the export-default rule for each relevant API level without looking it up
- [ ] You checked the `protectionLevel` of every custom permission before treating it as a control
- [ ] You ran every probe from **both** `adb shell` and the probe APK and recorded both columns
- [ ] You extracted a file the provider never intended to share
- [ ] You can explain the file-descriptor mechanism in terms of which process opened the file and when
      the kernel checked
- [ ] You established the exact bound of the traversal by testing what it cannot reach
- [ ] You walked the reach-through of at least one reached file rather than asserting impact
- [ ] You applied the `FileProvider` fix and verified it against a legitimate name, a traversal, and a
      symlink
- [ ] You noticed that fixing `openFile` alone leaves `query()` open
- [ ] Your write-up states that the sandbox did not fail
