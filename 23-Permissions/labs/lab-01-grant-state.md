# Lab 01 — Reading grant state without lying to yourself

> **Level:** Beginner
> **Time:** 60–90 minutes
> **Needs:** a device or emulator with `adb`, Python 3.6+, and `apktool`
> **Chapter:** [23-Permissions](../README.md) — §2.2, §3.1, §3.2, §3.12

---

## Why this lab exists

Almost every wrong permission finding in almost every mobile report comes from one mistake:
someone read the `requested permissions:` block of `dumpsys package` and reported its contents as
capabilities the app has.

That block is a manifest. It is a wish list. It is fully controlled by the developer, it has no
relationship to what the platform granted, and on a real app a large fraction of it is never
granted at all.

By the end of this lab you will be able to look at a raw `dumpsys package` capture and say, with
no tooling at all, exactly which permissions an app holds — and, more importantly, you will have
seen with your own eyes how big the gap is between asked-for and held on a real, shipped app.

## Objectives

1. Capture the permission state of a real installed app and separate it into the three lists the
   platform actually keeps.
2. Compute the fourth set — requested and never granted — and explain what is in it.
3. Resolve a permission's `protectionLevel` from the device rather than from a manifest.
4. Demonstrate that `dumpsys package` alone gives the wrong answer for an `appop`-flagged
   permission.
5. Read the permission-derived GID list and prove it is not the same as the process's live group
   list.
6. Audit a deliberately weak manifest and produce a findings list with honest severity.

## Setup

```bash
# host — confirm you have a device
adb devices
#   List of devices attached
#   80062527052150  device

# host — confirm Python
python3 --version

# host — a working directory OUTSIDE the repository
mkdir -p ~/lab-23-01 && cd ~/lab-23-01
```

You also need a target app. Any app with a reasonable permission surface will do; a browser is
ideal because browsers request a lot. The worked examples below use `com.android.chrome`, which is
present on almost every device.

```bash
# host — pick a target and confirm it exists
adb shell pm list packages | grep -i chrome
#   package:com.android.chrome
```

> **⚠️ If your device has no Chrome**
> Substitute any package from `adb shell pm list packages -3` (third-party) or
> `adb shell pm list packages -s` (system). The numbers in this lab will differ; the *structure*
> will not, and the structure is the lesson. Record your own numbers as you go.

---

## Part 1 — The three lists, by hand

### Step 1.1 — Capture

```bash
# host
adb shell dumpsys package com.android.chrome > chrome.txt
wc -l chrome.txt
#   3203 chrome.txt
```

Three thousand lines. The permission state is about a hundred and fifty of them. Everything else is
the resolver tables, the key set manager, and the dexopt state.

### Step 1.2 — Find the blocks

```bash
# host
grep -n 'declared permissions:\|requested permissions:\|install permissions:\|runtime permissions:\|gids=' chrome.txt
```

You should see something like:

```text
2914:    declared permissions:
2921:    requested permissions:
2981:    install permissions:
3014:      gids=[3002, 3003]
3015:      runtime permissions:
3067:    declared permissions:
3075:    requested permissions:
3126:    install permissions:
3156:      gids=[3002, 3003]
3157:      runtime permissions:
```

**Question 1.** Why does each block appear twice?

<details>
<summary>Answer</summary>

`dumpsys package` prints the same package under more than one heading — typically `Packages:` and
`Hidden system packages:` for an app that shipped on the system image and has since been updated.
The two blocks describe the updated APK and the factory one. Read the first, and if the two differ
materially, say which you used.

This is exactly the kind of detail a script must handle and a human must notice. It is why
[`../scripts/grant-state.py`](../scripts/grant-state.py) keeps the block with the most grant data
rather than the first one it sees.

</details>

### Step 1.3 — Read each block, and notice the punctuation

```bash
# host — the requested block
sed -n '2921,2980p' chrome.txt | head -20
```

```text
    requested permissions:
      android.permission.ACCESS_COARSE_LOCATION
      android.permission.ACCESS_FINE_LOCATION
      android.permission.CAMERA
      android.permission.INTERNET
      android.permission.REQUEST_INSTALL_PACKAGES
      ...
```

```bash
# host — the install block
sed -n '2981,3014p' chrome.txt | head -10
```

```text
    install permissions:
      android.permission.DOWNLOAD_WITHOUT_NOTIFICATION: granted=true
      com.google.android.c2dm.permission.RECEIVE: granted=true
      android.permission.INTERNET: granted=true
      android.permission.REQUEST_INSTALL_PACKAGES: granted=false
      ...
```

**The difference is one token.** Lines in the requested block have no `granted=` suffix. Lines in
the other two blocks do.

> **🧠 Mental Model**
> If a line has no `granted=`, you are looking at intent, not fact. That single character of
> punctuation is the difference between a finding and a fabrication.

### Step 1.4 — Count, by hand, before you use any tool

```bash
# host — requested
sed -n '/requested permissions:/,/install permissions:/p' chrome.txt | grep -c '^      [a-z]'

# host — install
sed -n '/install permissions:/,/User 0:/p' chrome.txt | grep -c 'granted='

# host — install, granted only
sed -n '/install permissions:/,/User 0:/p' chrome.txt | grep -c 'granted=true'

# host — runtime
sed -n '/runtime permissions:/,/disabledComponents/p' chrome.txt | grep -c 'granted='
```

Write your four numbers down. On the reference device they were:

| Set | Count |
|---|---|
| requested | 59 |
| install permissions | 25 (24 granted, 1 refused) |
| runtime permissions | 12 (12 granted) |
| **held** | **36** |

### Step 1.5 — The fourth set

Requested minus everything that appears in a grant block.

```bash
# host
sed -n '/requested permissions:/,/install permissions:/p' chrome.txt \
    | grep '^      [a-z]' | tr -d ' ' | sort -u > requested.txt

{ sed -n '/install permissions:/,/User 0:/p' chrome.txt
  sed -n '/runtime permissions:/,/disabledComponents/p' chrome.txt ; } \
    | grep 'granted=' | sed 's/^ *//; s/:.*//' | sort -u > listed.txt

comm -23 requested.txt listed.txt
```

**Question 2.** How many are there, and what is in the list?

<details>
<summary>Answer for the reference device</summary>

Twenty-two, in three groups.

Other vendors' permissions this app asks for and does not receive:

```text
com.sec.enterprise.knox.MDM_CONTENT_PROVIDER
com.google.android.apps.now.CURRENT_ACCOUNT_ACCESS
com.google.android.googlequicksearchbox.permission.LENS_SERVICE
com.google.android.apps.aicore.service.BIND_SERVICE
com.chrome.permission.DEVICE_EXTRAS
```

Platform permissions this build does not qualify for:

```text
android.permission.CAPTURE_KEYBOARD
android.permission.REPOSITION_SELF_WINDOWS
android.permission.USE_PINNED_WINDOWING_LAYER
```

And permissions that **do not exist on this platform version at all**:

```text
android.permission.FOREGROUND_SERVICE_CAMERA
android.permission.FOREGROUND_SERVICE_MICROPHONE
android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION
android.permission.CREDENTIAL_MANAGER_SET_ORIGIN
android.permission.QUERY_ADVANCED_PROTECTION_MODE
android.permission.HAND_TRACKING
android.permission.SCENE_UNDERSTANDING_FINE
```

That third group is a nice technique in itself. This Chrome build reports
`minSdk=32 targetSdk=36` while the device runs API 33, so it carries permission requests for a
platform the device has never seen. An app's unaccounted set tells you what platform it was
*written for*, independently of anything in its manifest.

**None of the twenty-two is a finding.** The correct report sentence is: "the app requests 59
permissions and holds 36; the 22-permission gap consists of other vendors' permissions, platform
permissions it does not qualify for, and permissions that do not exist on the tested platform."

</details>

### Step 1.6 — Now let the script do it

```bash
# host
python3 -B ~/Android-Pentesting-Notes/23-Permissions/scripts/grant-state.py chrome.txt
```

Compare its four counts with the ones you computed by hand. They should agree. If they do not,
find out why before continuing — the discrepancy is more instructive than the agreement.

```bash
# host — just the gap
python3 -B .../scripts/grant-state.py chrome.txt --unaccounted-only

# host — a report-ready table
python3 -B .../scripts/grant-state.py chrome.txt --markdown > chrome-grants.md
```

> **✅ Success criterion for Part 1**
> You can state, for your chosen app, the four counts, and you can name at least three permissions
> in the unaccounted set and explain why each one is there.

---

## Part 2 — Resolving a protection level from the device

A permission name tells you nothing. The level tells you everything.

### Step 2.1 — The declared block

```bash
# host
sed -n '/declared permissions:/,/requested permissions:/p' chrome.txt
```

```text
    declared permissions:
      com.android.chrome.permission.CHILD_SERVICE: prot=signature, INSTALLED
      com.android.chrome.permission.READ_WRITE_BOOKMARK_FOLDERS: prot=signature|privileged, INSTALLED
      com.android.chrome.TOS_ACKED: prot=signature|privileged, INSTALLED
      com.android.chrome.permission.C2D_MESSAGE: prot=signature, INSTALLED
      com.android.chrome.permission.DEBUG: prot=signature, INSTALLED
      com.android.chrome.permission.SHOW_COMPLIANCE_SCREEN: prot=signature|privileged, INSTALLED
```

**Question 3.** Three of those are `signature` and three are `signature|privileged`. Which set is
stronger, and why?

<details>
<summary>Answer</summary>

Plain `signature` is stronger. Every `|` in a `protectionLevel` is an **OR** that adds an
independent population that can obtain the permission. `signature|privileged` means "same signing
key **or** an allow-listed privileged app". On a vendor build the privileged app set can be dozens
of apps written by several contractors, so the permission's real trust boundary is the weakest of
them.

This is the single most misread fact about protection levels. Flags widen; they never narrow. See
[`../README.md`](../README.md) §3.3.

</details>

### Step 2.2 — `pm list permissions`

```bash
# host — one permission, in full
adb shell pm list permissions -f -g | grep -A5 'com.android.chrome.permission.DEBUG'
```

```text
  + permission:com.android.chrome.permission.DEBUG
    package:com.android.chrome
    label:null
    description:null
    protectionLevel:signature
```

Note `package:` — that is the **owner**, and it is the answer to a question the manifest cannot
answer. Try it without `-f`:

```bash
# host
adb shell pm list permissions | grep DEBUG
```

You get names and nothing else. A tester who runs the un-flagged version and reports "the app uses
a custom permission" has learned that a string exists.

### Step 2.3 — The single most useful command in the chapter

```bash
# host
adb shell dumpsys package permission com.android.chrome.permission.DEBUG
```

```text
Permission [com.android.chrome.permission.DEBUG] (...):
  sourcePackage=com.android.chrome
  uid=10107 gids=[] type=0 prot=signature
```

Four facts in three lines: who owns the definition, what level is enforced, which UID that owner
runs as, and — `gids=[]` — that this permission maps to no Linux group.

**Question 4.** Could a custom permission ever have a non-empty `gids` list?

<details>
<summary>Answer</summary>

No. The permission-to-GID mapping is defined only in `/system/etc/permissions/*.xml`, which comes
from `frameworks/base/data/etc/platform.xml` in AOSP and lives on a read-only partition. An app
cannot write there, so **no custom permission is ever kernel-enforced**. Every custom permission is
a Java string comparison inside `system_server` and nothing more.

That is worth internalising, because it bounds what a custom permission can ever be. See
[`../README.md`](../README.md) §3.5.

</details>

### Step 2.4 — Audit a manifest that is doing it wrong

```bash
# host
cd ~/Android-Pentesting-Notes/23-Permissions
python3 -B scripts/permission-audit.py --manifest examples/weak-permissions-AndroidManifest.xml
```

Before you read the tool's output, open
[`../examples/weak-permissions-AndroidManifest.xml`](../examples/weak-permissions-AndroidManifest.xml)
and write your own list of defects. There are ten planted, and the file names them at the bottom —
do not scroll down until you have written yours.

Then compare with the tool:

```text
  verdicts : NOT-A-BOUNDARY 3, UNOWNED 1, ENFORCEABLE 2

  #   VERDICT         LEVEL IN FORCE             PERMISSION
  1   NOT-A-BOUNDARY  normal                     com.example.weakperms.permission.INTERNAL_API
  2   NOT-A-BOUNDARY  signature|appop            com.example.weakperms.permission.OVERLAY_CONTROL
  3   NOT-A-BOUNDARY  dangerous                  com.example.weakperms.permission.SYNC
  4   UNOWNED         (unresolved)               com.example.suite.permission.MANAGE_SYNC
  5   ENFORCEABLE     signature|privileged       com.example.weakperms.permission.ADMIN
  6   ENFORCEABLE     signature|development      com.example.weakperms.permission.DEBUG_DUMP
```

**Question 5.** Row 1 has level `normal` even though the manifest does not say `normal` anywhere.
Where did that come from?

<details>
<summary>Answer</summary>

`<permission android:name="…INTERNAL_API" />` has no `android:protectionLevel` attribute at all.
The platform's default for an omitted level is `normal` — the weakest possible value. The tool
resolves it rather than reporting UNRESOLVED, because the platform's rule is unambiguous and
refusing to apply it would hide the highest-value finding in the whole area.

This is one grep, it produces zero false positives, and it should be the first thing you run
against any manifest:

```bash
grep -n '<permission ' AndroidManifest.xml | grep -v protectionLevel
```

</details>

**Question 6.** Row 6 is `ENFORCEABLE` and yet it is one of the ten planted defects. Explain.

<details>
<summary>Answer</summary>

`signature|development` genuinely cannot be obtained by an attacker's app — the tool's verdict is
correct on its own terms, which are "can an attacker obtain this by acting alone?".

The defect is what it does to **your testing**. The `development` flag makes the permission
grantable from the shell with `pm grant`. If you grant it during a test, forget, and then report
the resulting behaviour as reachable, you have reported something only a person with a USB cable
and developer options enabled can do. The tool's own description says exactly this, which is why
you read the descriptions and not just the verdict column.

</details>

> **✅ Success criterion for Part 2**
> You can resolve any permission's owner and level from a device in under ten seconds, and you can
> explain why `signature|privileged` is weaker than `signature`.

---

## Part 3 — The appop half nobody reads

### Step 3.1 — The contradiction

```bash
# host — what the permission database says
grep 'REQUEST_INSTALL_PACKAGES' chrome.txt
#       android.permission.REQUEST_INSTALL_PACKAGES: granted=false

# host — what the app-op state machine says
adb shell cmd appops get com.android.chrome REQUEST_INSTALL_PACKAGES
#   Uid mode: REQUEST_INSTALL_PACKAGES: allow
#   REQUEST_INSTALL_PACKAGES: allow
```

Permission: not granted. Op: allow.

**Question 7.** Which is right?

<details>
<summary>Answer</summary>

Both. They are two halves of one answer.

`REQUEST_INSTALL_PACKAGES` has `protectionLevel="signature|appop"`. The `signature` half fails —
Chrome is not signed with the platform key — so the permission grant is `false`. The `appop` half
is a separate, mutable, per-app switch, and it is `allow`.

For an `appop`-flagged permission the effective capability is a function of both. Reading only
`dumpsys package` and concluding "this browser cannot launch a package installer" is wrong, and
reading only `cmd appops` and concluding "it can" is also wrong. You report both, together.

This is the single most reliable way to produce a confidently wrong finding in this chapter, in
either direction.

</details>

### Step 3.2 — The full op picture

```bash
# host
adb shell cmd appops get com.android.chrome
```

```text
Uid mode: REQUEST_INSTALL_PACKAGES: allow
LEGACY_STORAGE: ignore
COARSE_LOCATION: allow
FINE_LOCATION: allow
CAMERA: allow
RECORD_AUDIO: allow
SYSTEM_ALERT_WINDOW: default; rejectTime=+215d1h22m53s81ms ago
MANAGE_EXTERNAL_STORAGE: default; rejectTime=+215d1h23m23s436ms ago
NO_ISOLATED_STORAGE: deny; rejectTime=+215d1h23m23s432ms ago
```

Three things to extract:

- **Every granted runtime permission has a shadowing op.** `CAMERA: allow` mirrors the runtime
  grant. An MDM or privacy tool can set the op to `ignore` and the camera API will return empty
  data rather than throw — a granted permission that yields nothing.
- **`default` is not `deny`.** It means "no explicit decision; defer to the permission".
- **`rejectTime` records when the app last *attempted* something it was refused.** That is attempt
  evidence, not capability evidence, and it is a genuinely useful forensic artefact.

**Question 8.** `SYSTEM_ALERT_WINDOW` shows `default` with a `rejectTime` about 215 days ago. What
does that tell you?

<details>
<summary>Answer</summary>

Something in this app asked for the ability to draw over other apps, roughly seven months ago, and
was refused. The app does not hold the capability now and has not since. It is not a finding —
but on a malware assessment, `rejectTime` on an overlay op is exactly the kind of thing you want to
know, because it says the code path *exists*.

</details>

---

## Part 4 — GIDs, and two lists that are not the same list

### Step 4.1 — The permission-derived list

```bash
# host
grep 'gids=' chrome.txt
#       gids=[3002, 3003]
```

**Question 9.** Chrome holds `READ_EXTERNAL_STORAGE` and `WRITE_EXTERNAL_STORAGE` as granted
runtime permissions. Why is there no storage GID in that list?

<details>
<summary>Answer</summary>

Because on modern Android there is no longer a storage GID mapping. Pull the device's own policy
file and look:

```bash
adb shell cat /system/etc/permissions/platform.xml | grep -A2 EXTERNAL_STORAGE
```

```xml
<!-- These are permissions that were mapped to gids but we need
     to keep them here until an upgrade from L to the current
     version is to be supported. ... -->
<permission name="android.permission.READ_EXTERNAL_STORAGE" />
<permission name="android.permission.WRITE_EXTERNAL_STORAGE" />
```

Declared with **no `<group>` child at all**. Scoped storage moved shared-storage enforcement to a
FUSE layer and to MediaProvider, and the old `sdcard_rw` (1015) / `sdcard_r` (1028) mechanism was
retired with it.

Reference tables that still list those AIDs against those permissions are describing an older
platform. Do not test for shared-storage access by looking at group membership on a modern device.

</details>

### Step 4.2 — The live list

```bash
# host — start the app first so it has a process
adb shell monkey -p com.android.chrome -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 2
PID=$(adb shell pidof com.android.chrome | awk '{print $1}')
adb shell cat /proc/$PID/status | grep -E '^(Uid|Gid|Groups)'
```

```text
Uid:    10107   10107   10107   10107
Gid:    10107   10107   10107   10107
Groups: 1079 3002 3003 9997 20107 50107
```

Two entries in `dumpsys`; six in `/proc`.

**Question 10.** Where do the other four come from?

<details>
<summary>Answer</summary>

They are not permission grants. Zygote adds them:

| GID | Source |
|---|---|
| `9997` | `AID_EVERYBODY` — every app process is in it, unconditionally |
| `20107` | The per-app **cache** GID, `20000 + appId'`, for cache quota accounting |
| `50107` | The per-app **shared** GID, `50000 + appId'` |
| `1079` | Not a permission GID and not in a range this chapter names with confidence — a platform or vendor group attached by the device's own configuration |

The last row is the honest one. When you meet a group you cannot name, read the device's own
`/system/etc/permissions/*.xml` and its AID configuration rather than guessing from a table written
against a different build. Saying "I could not resolve GID 1079 on this build" in a report is
fine; guessing is not.

The operational rule: `dumpsys` answers "which permissions produced groups?", `/proc/<pid>/status`
answers "what can this process actually do?". For "can this reach the network", look for `3003` in
the second one.

</details>

### Step 4.3 — Prove `3003` is what it looks like

If you have a spare app or emulator, install anything with no `INTERNET` permission and repeat
step 4.2. Its `Groups:` line will lack `3003`, and any socket call it makes will fail with
`EACCES` from the kernel — not with a Java `SecurityException`.

The exception type is a usable fingerprint. A framework permission denial arrives as
`SecurityException`; a missing `INTERNET` GID arrives as an `IOException` from the socket layer,
because there is no Java in the enforcement path at all.

---

## Part 5 — Write the finding

Take everything above and produce a permission section for a report. It should contain:

1. **A statement of held permissions**, not requested ones, with the count of each.
2. **A sentence about the gap**, so the reader knows you checked and that the gap is not a finding.
3. **A controls-observed subsection** naming the app's own `signature`-level permissions.
4. **Any genuine finding**, with resolved level, owner, and — if you are claiming reachability —
   the note that you have *not yet* proven it from an unprivileged app.

A model paragraph for the reference device:

> The application requests 59 permissions and holds 36 on the tested device (24 install-time, 12
> runtime). The 22-permission gap consists of permissions belonging to other vendors' applications
> that are not installed, platform permissions the application does not qualify for, and
> permissions introduced after the tested platform version; none represents a capability the
> application holds.
>
> **Controls observed.** All six permissions the application declares are signature-anchored
> (`signature` or `signature|privileged`). Three carry the `privileged` flag, which admits
> allow-listed system applications in addition to same-key applications; on this device that widens
> the population but does not admit a third-party application.
>
> **Note on `REQUEST_INSTALL_PACKAGES`.** The permission is not granted
> (`granted=false`), but the corresponding app-op is set to `allow`. The application's effective
> ability to trigger package installation is therefore governed by the op rather than by the
> permission, and both states are recorded here because either alone is misleading.

> **✅ Success criterion for the lab**
> You have produced a permission section that contains no sentence that could be disproved in ten
> seconds by whoever receives it.

---

## Hints

<details>
<summary>My grep for the blocks returns nothing</summary>

Some builds indent differently or use `runtime permissions` without the colon. Try a looser
pattern:

```bash
grep -n -i 'permissions:' chrome.txt
```

and read the surrounding lines. If the format has drifted far enough that
[`../scripts/grant-state.py`](../scripts/grant-state.py) parses nothing, that is itself worth
knowing — the script prints a clear error rather than silently reporting empty sets, which is the
behaviour you want from any tool that reads an unstable format.

</details>

<details>
<summary>`cmd appops get` says "Unknown command"</summary>

Older platforms use `adb shell appops get <pkg>` without `cmd`. Try both. On very old platforms
the op names differ from the permission names more than they do now.

</details>

<details>
<summary>`pidof` returns nothing</summary>

The app is not running. Launch it, or use:

```bash
adb shell ps -A | grep chrome
```

and take the PID from the second column. On some vendor builds `pidof` is absent entirely.

</details>

<details>
<summary>I cannot read /proc/&lt;pid&gt;/status for another app</summary>

On some builds `adb shell` is SELinux-denied from reading another app's `/proc` entries. Use a
debuggable app of your own and `run-as`, or an emulator with a userdebug build. If you cannot get
it at all, say so and move on — the `dumpsys` half of the lesson stands on its own.

</details>

---

## What to take away

- The `requested permissions:` block is a manifest. It is not evidence of anything.
- Held = granted install-time + granted runtime. Nothing else.
- The gap between requested and held is usually large and is usually not a finding — but you must
  be able to explain what is in it.
- A permission name means nothing; resolve the level and the owner from the device.
- Flags widen a protection level, never narrow it.
- For `appop`-flagged permissions, read both state machines or read neither.
- `dumpsys` gids and `/proc` Groups are different lists and answer different questions.

## Next

[Lab 02 — Permission squatting with two installable apps](lab-02-squatting.md) takes the ownership
question from Part 2 and makes it an experiment.

## Related

- [`../README.md`](../README.md) §2.2, §3.1, §3.2, §3.5, §3.12
- [`../cheatsheet.md`](../cheatsheet.md) — the command set on one page
- [`../scripts/grant-state.py`](../scripts/grant-state.py)
- [`../scripts/permission-audit.py`](../scripts/permission-audit.py)
- [`../examples/weak-permissions-AndroidManifest.xml`](../examples/weak-permissions-AndroidManifest.xml)
- [21-App-Sandbox](../../21-App-Sandbox/README.md) — where the GIDs come from, from the sandbox side
- [32-Manifest](../../32-Manifest/README.md) — the declaration audit this lab deliberately does not repeat
