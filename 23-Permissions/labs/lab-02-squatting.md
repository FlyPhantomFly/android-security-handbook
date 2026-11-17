# Lab 02 — Permission squatting with two installable apps

> **Level:** Intermediate
> **Time:** 2–3 hours
> **Needs:** a device or emulator you own, `adb`, the Android SDK build-tools, a JDK
> **Chapter:** [23-Permissions](../README.md) — §1.3, §3.4, §3.6
> **This is the chapter's signature lab.** Everything in it was measured on a physical device
> running Android 13 / API 33 before it was written down.

---

## Why this lab exists

The claim this chapter is built around is that **only `signature` is a real security boundary**.
You should not accept that from a document. This lab makes you build the apps, install them in
both orders, and watch the platform's own output tell you what happened.

You will finish with three results, one of which contradicts what most references say, and all
three of which you will have produced yourself.

## What you will prove

| # | Claim | How you prove it |
|---|---|---|
| 1 | A permission name is owned by whoever installs **first**. The naming convention reserves nothing. | Install two apps in each order and read `sourcePackage=` |
| 2 | On Android 13, the **second** app to declare an already-owned name **cannot install at all** — symmetrically, regardless of which is malicious | `INSTALL_FAILED_DUPLICATE_PERMISSION` |
| 3 | A permission an app **uses** but does not **declare** is unowned and fully squattable, and a third-party app signed with an unrelated key receives it at install with **no prompt** | `granted=true` on an app that has no relationship to anybody |

Result 2 is the one worth your attention. It is not what the textbook version of this attack says
happens, and knowing the difference changes what you write in a report.

## Objectives

1. Build four APKs from source with no Gradle and no Android Studio.
2. Establish ownership of a permission name and read it back from the platform.
3. Reproduce `INSTALL_FAILED_DUPLICATE_PERMISSION` in both directions.
4. Reproduce the working squat against a suite app, and demonstrate the grant to an unrelated
   third party.
5. Observe what happens to grants when the definer is uninstalled.
6. Establish that `pm grant` cannot help you here, and understand why.
7. Write the finding, with the correct impact for each of the two cases.

---

## Before you start

You are about to install apps that claim a permission namespace belonging to a fictional company.
That is harmless on a device you own and would be rude on anyone else's.

- **Use a device or emulator you own.** Not a client device, not a shared device.
- **Uninstall all four apps when you finish.** The cleanup commands are in Part 7 and they are not
  optional; a squatted permission name persists until its owner is removed.
- The four apps contain **no code at all**. `android:hasCode="false"` means no `classes.dex` is
  produced. They cannot run, cannot be launched, and do nothing but exist in the package database.

---

## Setup

```bash
# host — the SDK, wherever yours lives
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"          # or %LOCALAPPDATA%\Android\Sdk

# host — confirm the pieces
ls "$ANDROID_SDK_ROOT"/build-tools/
ls "$ANDROID_SDK_ROOT"/platforms/
java -version
adb devices
```

```bash
# host — build all four
cd ~/Android-Security-Handbook/23-Permissions/examples/squat-pair
./build-squat-pair.sh
```

```text
[*] build-tools : /home/you/Android/Sdk/build-tools/35.0.1
[*] platform    : /home/you/Android/Sdk/platforms/android-35/android.jar
[*] generating throwaway key a
[*] generating throwaway key b
[*] generating throwaway key c
[+] .../out/squatter.apk   (key a)
[+] .../out/victim.apk     (key b)
[+] .../out/suite.apk      (key b)
[+] .../out/probe.apk      (key c)
```

### The cast

| APK | Package | Key | What its manifest does |
|---|---|---|---|
| `squatter.apk` | `com.squat.first` | **A** | **Declares** `com.victim.notes.permission.READ_NOTES` at `normal`, and requests it |
| `victim.apk` | `com.victim.notes` | **B** | **Declares** the same name at `signature`, and guards an exported provider with it |
| `suite.apk` | `com.victim.suite` | **B** | **Uses** the name to guard an exported provider, and declares nothing |
| `probe.apk` | `com.third.probe` | **C** | Nothing but `<uses-permission>` for the name |

Three different signing keys. There is no signature relationship between the attacker and either
victim, and none between the probe and anybody.

Read all four manifests before you install anything. They are short, they are heavily commented,
and the comments state what each measurement will show. Reading them first means the results
confirm or contradict something you already had in your head, which is the only way an experiment
teaches anything.

- [`../examples/squat-pair/squatter-AndroidManifest.xml`](../examples/squat-pair/squatter-AndroidManifest.xml)
- [`../examples/squat-pair/victim-AndroidManifest.xml`](../examples/squat-pair/victim-AndroidManifest.xml)
- [`../examples/squat-pair/victim-suite-AndroidManifest.xml`](../examples/squat-pair/victim-suite-AndroidManifest.xml)
- [`../examples/squat-pair/probe-AndroidManifest.xml`](../examples/squat-pair/probe-AndroidManifest.xml)

### Baseline

```bash
# host — nothing of ours is installed
adb shell pm list packages | grep -E 'com.squat|com.victim|com.third'
# (no output)

# host — nobody owns the name
adb shell pm list permissions -f -g | grep -A4 READ_NOTES
# (no output)

adb shell dumpsys package permission com.victim.notes.permission.READ_NOTES
# Permissions:   (empty)
```

Write down that the permission does not exist. Everything after this is a change you caused.

---

## Part 1 — Ownership goes to the first installer

### Step 1.1

```bash
# host
adb install -r out/squatter.apk
#   Success
```

### Step 1.2 — Read the platform back

```bash
# host
adb shell pm list permissions -f -g | grep -A4 READ_NOTES
```

```text
  + permission:com.victim.notes.permission.READ_NOTES
    package:com.squat.first
    label:Read notes
    description:Squatter definition of READ_NOTES
    protectionLevel:normal
```

Read those five lines against the permission's own name. The name says `com.victim.notes`. The
`package:` line says `com.squat.first`.

The `description:` line is why the build script rewrites the string resource per app: it makes the
winner visible at a glance. `Squatter definition of READ_NOTES` means the attacker's XML is what
the platform is enforcing.

### Step 1.3 — The shorter command

```bash
# host
adb shell dumpsys package permission com.victim.notes.permission.READ_NOTES
```

```text
Permission [com.victim.notes.permission.READ_NOTES] (599fdf7):
  sourcePackage=com.squat.first
  uid=10137 gids=[] type=0 prot=normal
  perm=PermissionInfo{1fc9464 com.victim.notes.permission.READ_NOTES}
```

**Question 1.** What is `gids=[]` telling you, and could it ever be non-empty for a custom
permission?

<details>
<summary>Answer</summary>

It is the permission-to-Linux-group mapping, and it is empty. It can **never** be non-empty for a
custom permission: that mapping is defined only in `/system/etc/permissions/*.xml`, which is on a
read-only partition an app cannot write to.

So no custom permission is ever kernel-enforced. Every one of them is a Java string comparison
inside `system_server`. That is a hard ceiling on what a custom permission can ever be, and it is
worth knowing before you evaluate one. See [`../README.md`](../README.md) §3.5.

</details>

### Step 1.4 — The squatter granted itself

```bash
# host
adb shell dumpsys package com.squat.first | grep -A2 -E 'declared permissions:|requested permissions:|install permissions:'
```

```text
    declared permissions:
      com.victim.notes.permission.READ_NOTES: prot=normal, INSTALLED
    requested permissions:
      com.victim.notes.permission.READ_NOTES
    install permissions:
      com.victim.notes.permission.READ_NOTES: granted=true
```

All three blocks agree on one string in one package. The app declared a permission, requested it,
and was granted it at install with no prompt — because `normal` means exactly that.

**Question 2.** Is "an app can grant itself a permission" a vulnerability?

<details>
<summary>Answer</summary>

No, not in itself. An app requesting a `normal` permission is an app requesting a `normal`
permission; the fact that it also declared the permission changes nothing about the grant rule.

What matters is the *combination*: the app defined the rule **and** the rule admits everybody
**and** the name belongs, by convention, to somebody else. Take any one of those three away and
there is nothing here.

</details>

---

## Part 2 — The both-declare case, and the result that corrects the textbook

The victim now tries to install. It has done everything a careful developer is told to do: its own
namespace, `protectionLevel="signature"`, an exported provider guarded by it.

### Step 2.1

```bash
# host
adb install -r out/victim.apk
```

```text
adb: failed to install out/victim.apk: Failure [INSTALL_FAILED_DUPLICATE_PERMISSION:
Package com.victim.notes attempting to redeclare permission
com.victim.notes.permission.READ_NOTES already owned by com.squat.first]
```

**Stop and read that.** The victim did not install with a downgraded permission. The victim did
not install at all.

### Step 2.2 — Confirm nothing changed

```bash
# host
adb shell pm list permissions -f -g | grep -A4 READ_NOTES
#   ... description:Squatter definition of READ_NOTES
#       protectionLevel:normal
```

Unchanged. The failed install had no effect on the permission database.

### Step 2.3 — Now the other order

```bash
# host — clean slate
adb uninstall com.squat.first
#   Success

adb install -r out/victim.apk
#   Success

adb shell pm list permissions -f -g | grep -A4 READ_NOTES
```

```text
  + permission:com.victim.notes.permission.READ_NOTES
    package:com.victim.notes
    label:Read notes
    description:Victim definition of READ_NOTES
    protectionLevel:signature
```

```bash
# host — and now the attacker tries
adb install -r out/squatter.apk
```

```text
adb: failed to install out/squatter.apk: Failure [INSTALL_FAILED_DUPLICATE_PERMISSION:
Package com.squat.first attempting to redeclare permission
com.victim.notes.permission.READ_NOTES already owned by com.victim.notes]
```

**Question 3.** The refusal is symmetric — the second installer always loses, regardless of which
app is malicious and regardless of protection level. What does that do to the textbook description
of permission squatting?

<details>
<summary>Answer</summary>

The textbook version says the squatter's weaker definition silently **governs** the victim's
component. When both apps declare the name, that is **not** what a modern platform does. The
second installer is refused outright.

That does not make squatting harmless. It changes what it *is*:

| Configuration | What squatting is | Impact class |
|---|---|---|
| Both apps declare the name | An **install-denial** primitive: a malicious app already on the device makes a specific victim app permanently uninstallable, with no user-visible explanation beyond a generic install failure | Availability. Low to medium, and awkward to exploit at scale because the attacker must get there first |
| The victim **uses** a name it does not declare | The access-control bypass the textbook describes, in full | Confidentiality and integrity. High |

Report them differently. Calling the first case a "permission bypass" is wrong, and calling the
second case "hardened by modern Android" is also wrong.

**Note on versions.** This was measured on Android 13 / API 33. Older releases were more
permissive about same-name declarations. If your engagement covers a fleet with older devices,
measure on the oldest platform in scope rather than assuming this result carries backwards.

</details>

### Step 2.4 — Think about the denial as an attack

**Question 4.** Sketch how an attacker would use result 2 offensively.

<details>
<summary>Answer sketch</summary>

Publish an innocuous-looking app that declares the permission names used by a target application
you want to keep off devices — a competitor, a security tool, a banking app's companion. Users who
install yours first cannot install the target at all, and the failure message they see is generic.

It is not a strong attack. It requires distribution, it requires being first, and it is
conspicuous once anyone looks. But it is a real availability primitive with no exploit code in it
at all, and it is the reason the advice "namespace your permissions" is worth following even
though namespacing does not stop a determined attacker from typing your namespace.

</details>

---

## Part 3 — The case that still works

Reset, and reproduce the suite pattern: an app that **uses** a permission its sibling declares, on
a device where the sibling is absent.

### Step 3.1

```bash
# host — clean slate
adb uninstall com.victim.notes
adb shell pm list permissions -f -g | grep READ_NOTES
# (no output — the name is unowned again)
```

### Step 3.2 — Attacker first

```bash
# host
adb install -r out/squatter.apk
#   Success
```

### Step 3.3 — The victim installs happily

```bash
# host
adb install -r out/suite.apk
#   Success
```

No `INSTALL_FAILED_DUPLICATE_PERMISSION`, because `com.victim.suite` declares nothing. It only
*refers* to the name, in `android:readPermission` and `android:writePermission` on its exported
provider.

### Step 3.4 — Whose rule governs the victim's provider?

```bash
# host
adb shell dumpsys package permission com.victim.notes.permission.READ_NOTES
```

```text
Permission [com.victim.notes.permission.READ_NOTES] (8b8d463):
  sourcePackage=com.squat.first
  uid=10139 gids=[] type=0 prot=normal
```

The victim's exported provider is guarded by a permission the **attacker** owns, at a level the
**attacker** chose.

### Step 3.5 — Let the auditor say it

```bash
# host
cd ~/Android-Security-Handbook/23-Permissions
adb shell pm list permissions -f -g > /tmp/perms.txt
python3 -B scripts/permission-audit.py \
        --manifest examples/squat-pair/victim-suite-AndroidManifest.xml \
        --pm-list /tmp/perms.txt
```

```text
  verdicts : SQUATTED 1

  #   VERDICT         LEVEL IN FORCE             PERMISSION
  1   SQUATTED        normal                     com.victim.notes.permission.READ_NOTES

  [1] com.victim.notes.permission.READ_NOTES   (normal)
      level from : device (pm list permissions -f)
      owned by   : com.squat.first
      guards     : provider com.victim.suite.NotesProvider (read);
                   provider com.victim.suite.NotesProvider (write)
      REACHABLE  normal (base)
                 Any app that requests it. Granted silently at install, no prompt, no check.
```

Run it **without** `--pm-list` and compare:

```bash
python3 -B scripts/permission-audit.py \
        --manifest examples/squat-pair/victim-suite-AndroidManifest.xml
#   verdicts : UNOWNED 1
```

Same manifest, different verdict, because the second run had a device. That difference is the
whole reason this chapter's tooling takes device input and chapters 21's and 32's does not.

### Step 3.6 — The third party

```bash
# host
adb install -r out/probe.apk
#   Success

adb shell dumpsys package com.third.probe \
    | grep -E 'signatures=|requested permissions:|install permissions:|READ_NOTES'
```

```text
    signatures=PackageSignatures{da53932 version:4, signatures:[f5d40377], past signatures:[]}
    requested permissions:
      com.victim.notes.permission.READ_NOTES
    install permissions:
      com.victim.notes.permission.READ_NOTES: granted=true
```

`granted=true`.

Look at what that app is. Signed with a third key — compare the `signatures:[...]` value to the
squatter's and the victim's, they are all different. No relationship with anybody. No code. Its
entire content is one `<uses-permission>` line naming a permission belonging, by its name, to a
company it has never heard of.

**That is the claim from [`../README.md`](../README.md) §1.3, demonstrated end to end.** A
component in `com.victim.suite` that its developer believes is protected is reachable by any app on
the device that types one line.

**Question 5.** The provider in `suite.apk` has `android:name` pointing at a class that does not
exist, because the APK has no code. Does that weaken the demonstration?

<details>
<summary>Answer</summary>

It bounds it honestly, and you should say so in a report of your own work.

What is demonstrated: the permission that guards the component is owned by the attacker at a level
any app can obtain, and an unrelated app was granted it. That is a complete demonstration of the
**permission** half.

What is not demonstrated: that a query against that provider returns data, because there is no
provider implementation to return any. To demonstrate the full chain you would add a real
`ContentProvider` to `suite.apk` and a real `ContentResolver.query()` call to `probe.apk` — see
[`../examples/probe-app/`](../examples/probe-app/), which does contain code, and
[27-ContentProviders](../../27-ContentProviders/README.md), which owns provider exploitation.

Being precise about this boundary is not pedantry. It is the difference between "the permission
guarding this provider is attacker-controlled" — which you have proven — and "I read the victim's
notes", which you have not.

</details>

---

## Part 4 — What `pm grant` will and will not do

```bash
# host
adb shell pm grant com.third.probe com.victim.notes.permission.READ_NOTES
```

```text
Exception occurred while executing 'grant':
java.lang.SecurityException: Permission com.victim.notes.permission.READ_NOTES requested by
com.third.probe is not a changeable permission type
    at com.android.server.pm.permission.PermissionManagerServiceImpl.grantRuntimePermissionInternal(...)
    at com.android.server.pm.permission.PermissionManagerServiceImpl.grantRuntimePermission(...)
    at com.android.server.pm.permission.PermissionManagerService.grantRuntimePermission(...)
    at com.android.server.pm.PackageManagerShellCommand.runGrantRevokePermission(...)
```

**Question 6.** Why does the shell refuse, when the app already has the permission?

<details>
<summary>Answer</summary>

`pm grant` operates on **runtime** permissions and on permissions carrying the `development` flag.
A `normal` permission's grant was decided at install and lives in
`/data/system/packages.xml`; there is no per-app runtime state for `pm grant` to write into. The
error message says so precisely: "not a changeable permission type".

Contrast with a real runtime permission, which does work:

```bash
adb shell pm revoke com.android.chrome android.permission.CAMERA
adb shell dumpsys package com.android.chrome | grep 'permission.CAMERA: granted'
#   android.permission.CAMERA: granted=false, ...
adb shell pm grant com.android.chrome android.permission.CAMERA
#   android.permission.CAMERA: granted=true, ...
```

(Restore whatever state you found. Leaving a device with permissions you revoked is a change you
made to somebody's environment.)

The free bonus in that stack trace is a map of the code path, and every class in it is a real AOSP
file:
`frameworks/base/services/core/java/com/android/server/pm/PackageManagerShellCommand.java`,
`.../pm/permission/PermissionManagerService.java`,
`.../pm/permission/PermissionManagerServiceImpl.java`. The same sequence, in the other direction,
is what the `PermissionController` app calls when a user taps Allow.

</details>

---

## Part 5 — What happens when the definer leaves

```bash
# host
adb uninstall com.squat.first
#   Success

adb shell pm list permissions -f -g | grep READ_NOTES
# (no output)

adb shell dumpsys package com.third.probe \
    | grep -E 'requested permissions:|install permissions:' -A2
```

```text
    requested permissions:
      com.victim.notes.permission.READ_NOTES
```

The permission is gone from the device entirely, and the probe's `install permissions:` block no
longer contains it. The probe still **requests** it — that is in its manifest and cannot change —
but it no longer **holds** it.

**Question 7.** A user reports that a feature in a suite app stopped working after they uninstalled
a different app from the same vendor. What is your first hypothesis?

<details>
<summary>Answer</summary>

The uninstalled app was the one that **declared** the permission the still-installed app relies on.
Removing it destroyed the definition and every grant of it, so the surviving app's component is now
guarded by a permission nobody defines — which means nobody can be granted it.

This is the everyday, non-malicious face of the same mechanism, and it is the answer to a question
in [`../faq.md`](../faq.md) that sounds naive: *why did the permission disappear after a
reinstall?*

It is also the reason the correct fix for a suite is "every member declares the permission
identically", not "one member declares it and the others reference it".

</details>

---

## Part 6 — Write the finding

Produce two write-ups, because the two configurations are different findings.

### Finding A — the suite case

Include:

- The permission name, its **owner on the device** (`sourcePackage=`), and its **level**.
- The victim component it guards, and the fact that the victim does not declare the permission.
- The probe app's manifest — all four lines of it — and the `granted=true` output.
- Severity, argued. Not "High because permissions", but "High because an unprivileged application
  signed by an unrelated key obtains the permission that guards an exported provider, at install,
  with no user interaction".
- The bound on what you proved: the permission is obtainable; whether the provider returns
  anything worth having is a separate question you have or have not answered.
- The remediation, which is two things and not one:
  1. Every app in the suite declares the permission identically at `protectionLevel="signature"`,
     so that no install order leaves the name unowned.
  2. The component re-checks the caller in code with
     `PackageManager.checkSignatures(Process.myUid(), Binder.getCallingUid())`, which consults
     signing certificates directly and cannot be squatted at all. See
     [`../examples/SignatureGuardedService.java`](../examples/SignatureGuardedService.java).

### Finding B — the install-denial case

Include:

- Both `INSTALL_FAILED_DUPLICATE_PERMISSION` messages, showing the symmetry.
- The impact framed as **availability**, not confidentiality.
- The honest note that the attacker must install first, which limits practicality.
- The platform version you measured on, and a statement that older platforms may behave
  differently.

> **Success criterion for the lab**
> Two findings, with different severities and different impact classes, each supported by output
> you produced. Neither of them says "permission squatting allows an attacker to downgrade the
> victim's protection level", because you have measured that it does not.

---

## Part 7 — Clean up. Not optional.

```bash
# host
adb uninstall com.squat.first
adb uninstall com.victim.notes
adb uninstall com.victim.suite
adb uninstall com.third.probe

# host — confirm
adb shell pm list packages | grep -E 'com.squat|com.victim|com.third'
# (no output)
adb shell pm list permissions -f -g | grep READ_NOTES
# (no output)

# host — remove the build output and the throwaway keys from the repository
cd ~/Android-Security-Handbook/23-Permissions/examples/squat-pair
rm -rf out/
```

That last step matters beyond tidiness. `out/` contains four APKs and three signing keystores. APKs
are on this repository's artefact blocklist, and a signing key in version control is worse than an
APK. The directory is git-ignored, but ignored is not the same as absent.

---

## Hints

<details>
<summary>build-squat-pair.sh cannot find the SDK</summary>

Set it explicitly:

```bash
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
```

On Windows with Git Bash:

```bash
export ANDROID_SDK_ROOT="$LOCALAPPDATA/Android/Sdk"
```

The script picks the newest `build-tools/*` and the newest `platforms/*/android.jar` it finds. If
you have none, install them with `sdkmanager "build-tools;35.0.1" "platforms;android-35"`.

</details>

<details>
<summary>apksigner is missing</summary>

Recent build-tools ship `apksigner.bat` on Windows rather than a shell wrapper. The script runs
`java -jar "$BT/lib/apksigner.jar"` for exactly this reason, which works everywhere. If that jar is
absent your build-tools install is incomplete; reinstall it.

</details>

<details>
<summary>Install fails with INSTALL_FAILED_TEST_ONLY or a signature error</summary>

You are probably re-installing over a copy signed with a different throwaway key from an earlier
run. Uninstall first:

```bash
adb uninstall com.squat.first
```

If you regenerated the keys (deleted `out/*.jks`), every previously installed app must be
uninstalled before the new ones will go on.

</details>

<details>
<summary>The victim installs successfully instead of failing</summary>

Three possibilities, in order of likelihood.

1. The squatter is not actually installed. Check with
   `adb shell pm list packages | grep squat`.
2. You are on a platform version that handles same-name declarations differently. **This is a
   result, not a problem** — record your platform version and what you saw. The version at which
   this behaviour tightened is exactly the kind of thing worth measuring rather than asserting.
3. Your device deduplicated by signature in a way the reference device did not. Check with
   `adb shell dumpsys package permission com.victim.notes.permission.READ_NOTES` and see which
   `sourcePackage` and `prot` survived.

</details>

<details>
<summary>The probe does not get granted=true</summary>

Check the ownership first:

```bash
adb shell dumpsys package permission com.victim.notes.permission.READ_NOTES
```

If `prot=signature`, the victim won the race and the probe correctly gets nothing — that is the
system working. Uninstall everything and redo Part 3 in the right order.

If there is no permission record at all, nobody owns the name, and a permission nobody defines
cannot be granted. Install the squatter first.

</details>

<details>
<summary>My device refuses to install unsigned or sideloaded APKs</summary>

The APKs are signed, with v2/v3 schemes, by `apksigner`. If the device still refuses, it is a
vendor policy on sideloading. An emulator image (`sdk_gphone` AVD) has no such policy and every
measurement in this lab reproduces on one.

</details>

---

## What to take away

- A permission name has exactly one owner, and ownership goes to whoever installed first.
  Namespacing is a convention, not a check.
- On Android 13 the both-declare case is an **install denial**, symmetric, not a silent downgrade.
  Measure this on the oldest platform in your scope rather than assuming.
- The suite case — used but not declared — is fully effective, and the grant reaches an entirely
  unrelated app with no prompt.
- Uninstalling the definer destroys the permission and every grant of it.
- `pm grant` cannot touch a `normal` permission, because there is no runtime state for it to write.
- The fix is two-layered: declare identically at `signature` across the suite, **and** re-check the
  caller in code with `checkSignatures`, which nothing an attacker installs can influence.

## Next

[Lab 03 — Borrowing a privileged app's permissions](lab-03-confused-deputy.md) moves from
"obtaining a permission" to the more valuable "never obtaining it and using it anyway".

## Related

- [`../README.md`](../README.md) §1.3, §3.4, §3.6
- [`../examples/squat-pair/`](../examples/squat-pair/) — the four manifests and the build script
- [`../examples/SignatureGuardedService.java`](../examples/SignatureGuardedService.java) — the remediation, as code
- [`../scripts/permission-audit.py`](../scripts/permission-audit.py)
- [`../faq.md`](../faq.md) — "why did the permission disappear after reinstall?"
- [27-ContentProviders](../../27-ContentProviders/README.md) — what to do once the permission is yours
- [21-App-Sandbox](../../21-App-Sandbox/README.md) — `manifest-exposure.py`, which prints `NOT-A-BOUNDARY` for exactly this class
