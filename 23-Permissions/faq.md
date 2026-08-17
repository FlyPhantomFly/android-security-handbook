# 23 — Permissions · FAQ

Real questions, answered directly. Including the ones people feel stupid asking, which are usually
the ones whose answers matter most.

Answers marked **measured** were verified on a physical device running Android 13 / API 33.

---

### 1. What is the difference between a permission and a GID?

A **permission** is a string. The platform keeps, for each installed app, a set of permission
strings it has been granted. When an app calls a guarded API, `system_server` checks whether that
string is in the caller's set, and throws `SecurityException` if it is not. That is Java code, in a
different process, reached over Binder.

A **GID** is a Linux supplementary group ID. It is a number the kernel attaches to a process, and
the kernel consults it on every file, device and socket permission decision — the same mechanism
that decides whether you can read `/etc/shadow` on a server.

They meet in exactly one place. A small set of permissions are *implemented as* group membership.
`/system/etc/permissions/platform.xml` says:

```xml
<permission name="android.permission.INTERNET">
    <group gid="inet" />
</permission>
```

so "holding `INTERNET`" and "being in group 3003" are the same fact. When the app is installed,
`PackageManagerService` walks the granted install-time permissions through that mapping and stores
a GID list; when the process is forked, Zygote installs that list with `setgroups()` before
dropping to the app's UID.

Three consequences, and they are the practical reason to keep the two words apart:

- A GID-backed permission is enforced **by the kernel**, so no hook inside the app can affect it.
- It is fixed **at process creation**, so it cannot be revoked from a running process — which is
  why none of them is ever `dangerous`.
- **No custom permission can ever be one.** Only `/system/etc/permissions/*.xml` creates the
  mapping, and that is on a read-only partition an app cannot write to. Every custom permission's
  record shows `gids=[]`, always.

See [README.md](README.md) §3.5.

---

### 2. The app requested a permission. Does it have it?

No. Not without checking.

"Requested" is a line of XML in the manifest. It is a statement of intent by the developer and it
has no effect on what the app can do.

`dumpsys package <pkg>` prints three blocks, and the distinguishing feature is one token:

```text
    requested permissions:
      android.permission.CAMERA                      <- no "granted=". INTENT.
    install permissions:
      android.permission.INTERNET: granted=true      <- FACT
    runtime permissions:
      android.permission.CAMERA: granted=true, ...   <- FACT
```

**If a line has no `granted=`, you are looking at intent.**

The gap is usually large. **Measured**: Chrome on the test device requested 59 permissions and held
36. Twenty-two appeared in *no* grant block at all — other vendors' permissions it does not
qualify for, and permissions that do not exist on the tested platform version.

Reporting anything from the requested block as a capability is the single most common error in this
area, and it is disprovable by the reader in ten seconds.

---

### 3. Why does my custom permission not protect anything?

Almost certainly because you wrote this:

```xml
<permission android:name="com.example.permission.INTERNAL_API" />
```

and no `android:protectionLevel`. The default is **`normal`**, and `normal` means: granted to any
app that requests it, silently, at install, with no prompt and no check of any kind.

So an attacker adds one line to their own manifest:

```xml
<uses-permission android:name="com.example.permission.INTERNAL_API" />
```

and holds your permission. There is no step in that chain where anything about the attacker is
examined — not the signature, not the package name, not the installer, not the user.

Set `android:protectionLevel="signature"`. And then do the second thing, because the level alone is
not sufficient: check the caller in code with
`PackageManager.checkSignatures(Process.myUid(), Binder.getCallingUid())`, which consults signing
certificates directly and cannot be squatted. See
[examples/SignatureGuardedService.java](examples/SignatureGuardedService.java).

The one-grep check for this, with zero false positives:

```bash
grep -n '<permission ' AndroidManifest.xml | grep -v protectionLevel
```

---

### 4. Is `dangerous` good enough for an internal API?

No. It buys you one dialog, and everything about that dialog favours the attacker.

The attacker chooses **when** it appears — right after a screen that makes it look necessary. The
attacker chooses the surrounding narrative, and users grant permissions to apps they have just
chosen to install. The dialog's text is written by **your** developers, for a legitimate use case,
so it reads as reassuring. And the attacker can ask again; two refusals are needed before "don't
ask again" engages.

Developers usually reach for `dangerous` because `signature` "didn't work in debug". That is not a
`signature` problem; it is a signing-config problem. Your debug build and your release build are
signed with different keys, so a two-app suite where one side is debug and the other is release
will genuinely fail the signature check. Fix the signing config, not the protection level.

---

### 5. Why is `signature|privileged` weaker than `signature`?

Because every `|` is an **OR that adds a population**.

`signature` admits apps signed with your key. `signature|privileged` admits apps signed with your
key **or** allow-listed apps in `/system/priv-app`. On a vendor build that second population can be
dozens of apps written by several different contractors, and the permission's real trust boundary
is the weakest of them.

Flags widen. They never narrow. This is the most misread fact about protection levels, and it is
why [scripts/permission-audit.py](scripts/permission-audit.py) prints one row per population rather
than one verdict per permission — so that the arithmetic is visible.

---

### 6. What is `appop`?

An **App Op** is a per-app, per-operation mode value held by `AppOpsService` in `system_server`. It
is a completely separate state machine from permissions: its own storage
(`/data/system/appops.xml`), its own API, its own modes (`allow`, `ignore`, `deny`, `default`,
`foreground`), and it can be changed at runtime by the system, an MDM, or a privacy tool.

When a permission's `protectionLevel` carries the `appop` flag, the effective answer is a function
of **both** the permission grant and the op mode.

**Measured**, on the test device, for `REQUEST_INSTALL_PACKAGES` (`signature|appop`):

```text
# adb shell dumpsys package com.android.chrome
      android.permission.REQUEST_INSTALL_PACKAGES: granted=false

# adb shell cmd appops get com.android.chrome REQUEST_INSTALL_PACKAGES
Uid mode: REQUEST_INSTALL_PACKAGES: allow
```

Permission: not granted. Op: allow. Neither output alone tells you what this browser can do.

Two things that trip people up. `default` is **not** `deny` — it means "no explicit decision, defer
to the permission". And an op set to `ignore` makes the API return **empty data rather than throw**,
so a granted permission can yield nothing at all with no error anywhere.

For any `appop`-flagged permission, read both or read neither.

---

### 7. Can an app grant itself a permission?

Yes, and it is completely mundane.

An app can declare a permission and request it in the same manifest, and at `normal` level it is
granted at install. **Measured**, from a two-file app with no code in it:

```text
    declared permissions:
      com.victim.notes.permission.READ_NOTES: prot=normal, INSTALLED
    requested permissions:
      com.victim.notes.permission.READ_NOTES
    install permissions:
      com.victim.notes.permission.READ_NOTES: granted=true
```

That is not a vulnerability by itself — the app requested a `normal` permission and got it, which
is what `normal` means.

What matters is the combination: the app defined the rule, **and** the rule admits everybody,
**and** the name belongs, by convention, to somebody else. Take any one away and there is nothing
here. Put all three together and you have permission squatting.

What an app **cannot** do is grant itself a `dangerous` permission (only the user can), a
`signature` permission belonging to another app (it would need that app's key), or any permission
via `pm grant` (that is the shell, not the app).

---

### 8. Why did the permission disappear after a reinstall?

Because the app that **owned the definition** was uninstalled or reinstalled in a different order.

A permission string on a device has exactly one owning package — its `sourcePackage`. If that
package is removed, the definition ceases to exist, and **every grant of it evaporates with it**.

**Measured**:

```text
$ adb uninstall com.squat.first
Success
$ adb shell pm list permissions -f -g | grep READ_NOTES
(nothing)
$ adb shell dumpsys package com.third.probe
    requested permissions:
      com.victim.notes.permission.READ_NOTES
    (no install permissions block containing it)
```

The other app still *requests* the permission — that is in its manifest and cannot change — but no
longer *holds* it.

This is also the everyday, non-malicious version of the same mechanism: a user uninstalls one app
from a vendor's suite, and a feature in a *different* app from that suite stops working, because
the uninstalled one was the one that declared the permission.

The fix is that **every app in a suite declares the permission identically**, rather than one
declaring it and the others merely referencing it.

---

### 9. Two apps declare the same permission name. What happens?

The first one installed owns it. The second one **cannot install at all**.

**Measured**, on Android 13:

```text
$ adb install -r squatter.apk
Success
$ adb install -r victim.apk
Failure [INSTALL_FAILED_DUPLICATE_PERMISSION: Package com.victim.notes attempting to
redeclare permission com.victim.notes.permission.READ_NOTES already owned by com.squat.first]
```

and symmetrically in the other order — the second installer always loses, regardless of which app
is malicious and regardless of protection level.

**This corrects the textbook.** The commonly repeated version of permission squatting says the
squatter's weaker definition silently *governs* the victim's component. When both apps declare the
name, that is not what a modern platform does.

It does not make squatting harmless; it changes what it *is*. Both-declare is an **install-denial**
primitive: a malicious app already on a device can make a specific victim app permanently
uninstallable. That is an availability finding, not a confidentiality one, and you report it
differently.

The case that still works as an access-control bypass is question 10.

---

### 10. So when does permission squatting actually work?

When the victim **uses** a permission it does not **declare** — which is the standard multi-app
suite pattern.

```
com.vendor.core      DECLARES com.vendor.permission.SYNC at signature
com.vendor.reader    USES it to guard a provider, declares nothing
```

Install the reader without core, and nobody owns `com.vendor.permission.SYNC`. An attacker declares
it at `normal`, installs, and becomes its owner. No `INSTALL_FAILED_DUPLICATE_PERMISSION` fires,
because the reader never declared anything.

**Measured**, end to end: the squatter installed first at `normal`; the suite app installed
successfully afterwards; `dumpsys package permission` showed `sourcePackage=com.squat.first`,
`prot=normal`; and an entirely unrelated fourth app, **signed with a third key** and containing
nothing but one `<uses-permission>` line, received `granted=true` at install with no prompt.

That is the whole claim of this chapter demonstrated in four manifests. Reproduce it yourself:
[labs/lab-02-squatting.md](labs/lab-02-squatting.md).

---

### 11. Why can I not revoke `INTERNET`?

Because it is not a framework permission at runtime — it is a Linux group.

The group list is installed by `setgroups()` inside the Zygote child, immediately before it drops
to the app's UID. That order is mandatory: after `setresuid()` the process has lost `CAP_SETGID`
and can no longer change its own groups. There is no mechanism for anything else to change a
running process's group list either.

So revoking `INTERNET` from a running app would require **killing the app**. That is why every
GID-backed permission is an install-time permission and none of them is `dangerous`: the runtime
permission model requires revocability, and this mechanism cannot provide it.

It is also why you cannot Frida your way past it. Hook `checkSelfPermission` to return
`PERMISSION_GRANTED` and the app will believe it has networking; every `socket()` call will still
return `EACCES` from the kernel, because the kernel was never consulting the app's belief. Doing
that once, deliberately, is the clearest possible lesson in the difference between defeating a
*check* and defeating a *control*.

---

### 12. `dumpsys` says `gids=[3002, 3003]` but `/proc/<pid>/status` shows six groups. Why?

They are different lists answering different questions.

**Measured**, same app, same moment:

```text
# adb shell dumpsys package com.android.chrome | grep gids=
      gids=[3002, 3003]

# adb shell cat /proc/18665/status | grep Groups
Groups: 1079 3002 3003 9997 20107 50107
```

`dumpsys` shows the **permission-derived** list — the groups produced by walking the granted
install permissions through `platform.xml`. The live process has four more, and none of them is a
permission:

| GID | Where it comes from |
|---|---|
| `9997` | `AID_EVERYBODY` — every app process, unconditionally |
| `20107` | The per-app cache GID, `20000 + appId'` |
| `50107` | The per-app shared GID, `50000 + appId'` |
| `1079` | Not a permission GID and not in a range this chapter names with confidence — a platform or vendor group from the device's own configuration |

That last row is deliberate, and worth imitating. When you meet a group you cannot name, read the
device's own `/system/etc/permissions/*.xml` and AID configuration rather than guessing from a
table written against a different build. "I could not resolve GID 1079 on this build" is a fine
sentence in a report; a wrong guess is not.

Practical rule: `dumpsys` answers "which permissions produced groups?". `/proc/<pid>/status`
answers "what can this process actually do?" — and for "can it reach the network", that is the one
to read.

---

### 13. The app holds `READ_EXTERNAL_STORAGE` but has no storage GID. Is that a bug?

No. On modern Android there is no longer a storage GID.

**Measured** — the device's own `platform.xml`:

```xml
<!-- These are permissions that were mapped to gids but we need
     to keep them here until an upgrade from L to the current
     version is to be supported. ... -->
<permission name="android.permission.READ_EXTERNAL_STORAGE" />
<permission name="android.permission.WRITE_EXTERNAL_STORAGE" />
```

Declared with **no `<group>` child at all**, and the comment explains why the empty declarations
survive. Scoped storage moved shared-storage enforcement to a FUSE layer and to MediaProvider, and
the old `sdcard_rw` (1015) / `sdcard_r` (1028) mechanism went with it.

Reference tables that still list those AIDs against those permissions are describing an older
platform. Do not test shared-storage access by looking at group membership on a modern device.

---

### 14. Why does the app hold a permission its manifest never asked for?

Almost always `<split-permission>` in `platform.xml`.

A split maps an old permission onto newer, narrower ones for apps targeting below a given SDK. It
is a backwards-compatibility shim: a legacy app that never knew the newer permissions existed is
handed them so it keeps working.

**Measured**, sixteen split blocks on the test device, including:

```xml
<split-permission name="android.permission.ACCESS_FINE_LOCATION">
    <new-permission name="android.permission.ACCESS_COARSE_LOCATION" />
</split-permission>
<split-permission name="android.permission.ACCESS_FINE_LOCATION" targetSdk="29">
    <new-permission name="android.permission.ACCESS_BACKGROUND_LOCATION" />
</split-permission>
<split-permission name="android.permission.READ_EXTERNAL_STORAGE" targetSdk="33">
    <new-permission name="android.permission.READ_MEDIA_IMAGES" />
</split-permission>
```

Read the `targetSdk` attribute carefully — its meaning is the opposite of first impressions. A split
with `targetSdk="N"` applies to apps targeting **below** N. A split with **no** `targetSdk` applies
always: anything requesting `ACCESS_FINE_LOCATION` also receives `ACCESS_COARSE_LOCATION`, on every
version.

So: before you report a granted-but-not-requested permission as an anomaly, pull the file and grep
for it inside a `<new-permission>` element. This is the most common false positive produced by
home-grown permission tooling.

---

### 15. Which of `checkCallingPermission` and `checkCallingOrSelfPermission` should I use?

`checkCallingPermission`. Always, for authorisation.

The `OrSelf` variant sounds more thorough because the name is longer. It is the opposite.

```java
// ContextImpl -- shape
public int checkCallingPermission(String permission) {
    int pid = Binder.getCallingPid();
    if (pid != Process.myPid()) {
        return checkPermission(permission, pid, Binder.getCallingUid());
    }
    return PackageManager.PERMISSION_DENIED;      // no caller -> fail CLOSED
}

public int checkCallingOrSelfPermission(String permission) {
    return checkPermission(permission, Binder.getCallingPid(), Binder.getCallingUid());
}
```

`checkCallingPermission` tests whether there is a caller and denies when there is not.
`checkCallingOrSelfPermission` does not test — so when there is no Binder transaction in progress,
`Binder.getCallingUid()` returns the **current process's own UID**, and the check silently becomes
"do I hold this permission". For a privileged app the answer is always yes, and the method
authorises everybody.

"No transaction in progress" is easier to reach than it sounds: post the work to a `Handler`, hand
it to an `Executor`, do it on a background thread, or call it from your own `onCreate`.

It is one grep, and every hit needs one question — *what thread does this run on?*

```bash
grep -rn 'checkCallingOrSelfPermission\|enforceCallingOrSelfPermission' jadx-out/
```

---

### 16. If I hook `checkSelfPermission` with Frida, have I bypassed a permission?

No. You have changed the app's **belief** about itself.

`checkSelfPermission` is the app asking a question about itself, so that it can decide whether to
bother making a call that would fail. It is feature detection. The enforcement is somewhere else
entirely: inside `system_server` for framework permissions, and inside the kernel for GID-backed
ones. Neither consults the app's belief.

Hooking it *is* legitimately useful — it lets you explore a code path that is gated behind a
permission you do not have, and see what the app *would* do. What it does not do is make the
subsequent API call succeed.

Two rules if you do it. Label the transcript as modified, so nobody mistakes it for an unmodified
run — [scripts/hook-permission-checks.js](scripts/hook-permission-checks.js) prints a banner and
prefixes every line with `[FORCED]` for exactly this reason. And never write it up as a bypass.

---

### 17. Why does my probe app see nothing, even though the component is exported?

Package visibility. From `targetSdkVersion` 30 an app can only see packages it has declared an
interest in.

The failure is **silent**. A filtered package does not produce a `SecurityException`; it produces
an empty list, a null resolver result, a `NameNotFoundException`, or an
`ActivityNotFoundException` — all of which look exactly like "the component is not reachable".

Fix it in your probe's manifest:

```xml
<queries>
    <package android:name="com.target.app" />
    <provider android:authorities="com.target.app.provider" />
</queries>
```

then rebuild and reinstall. Note that providers are matched by **authority**, not by package, which
is the form to use when you do not know the owning package.

`QUERY_ALL_PACKAGES` also works and is `normal` level, so it is granted on request — but a probe
holding it is slightly less representative of a store-published app, since Play policy restricts it
heavily. Prefer naming your targets.

This is the single most common reason a home-made test app reports a false negative.

---

### 18. Why does reaching a component from `adb shell` not prove anything?

Because `adb shell` is not an app.

It runs as **UID 2000**, in the `shell` SELinux domain, and the platform hands that UID permissions
by policy that no installed package could ever request. **Measured**, from the device's own
`platform.xml`:

```xml
<assign-permission name="android.permission.INTERNET" uid="shell" />
```

Those `<assign-permission>` grants attach to a system UID, belong to no package, and appear in no
`dumpsys package` block at all. There is no way for an app to obtain them.

So `adb shell am start`, `adb shell content query` and `adb shell service call` establish a
**reachability upper bound**. If the shell cannot reach something, an app certainly cannot. If the
shell *can*, you have learned nothing about the app case.

The only proof is a plain third-party app. **Measured**, from
[examples/probe-app/](examples/probe-app/) on the test device:

```text
I PROBE  :   package = com.probe.unprivileged
I PROBE  :   uid     = 10146   (adb shell is 2000)
I PROBE  : probe=perm target=android.permission.INTERNET
I PROBE  : RESULT: checkSelfPermission(android.permission.INTERNET) = -1  DENIED
```

The shell has `INTERNET`; the probe does not, because it did not ask. That is the whole difference,
and it is why every reachability claim in this repository is made from a probe app.

---

### 19. `pm grant` says "not a changeable permission type". What now?

Nothing — that is the platform working correctly.

**Measured**:

```text
$ adb shell pm grant com.third.probe com.victim.notes.permission.READ_NOTES
java.lang.SecurityException: Permission com.victim.notes.permission.READ_NOTES requested by
com.third.probe is not a changeable permission type
```

`pm grant` operates on **runtime** permissions and on permissions carrying the `development` flag.
A `normal` permission's grant was decided at install and lives in `/data/system/packages.xml`;
there is no per-app runtime state for `pm grant` to write into.

If you want the app to hold a `normal` permission, put `<uses-permission>` in its manifest and
reinstall. That is the only route, and it is also the attacker's route — which is the point.

And a warning that runs the other way: if a permission carries `development` and `pm grant` *does*
work, do not report the resulting behaviour as reachable by an attacker. You demonstrated what a
person with a USB cable and developer options enabled can do.

---

### 20. `shouldShowRequestPermissionRationale` returns `false` but the permission is denied. Why?

Because it is a three-state variable compressed into a boolean, and the compression is lossy.

It returns `false` in **two** completely different situations: the user has never been asked, and
the user has permanently refused ("don't ask again"). It returns `true` only in the middle case,
where the user has refused at least once without selecting the permanent option.

To distinguish them you need a third input — whether your app has ever requested it before, which
you must record yourself:

| Granted? | Rationale | Requested before? | State |
|---|---|---|---|
| No | false | no | Never asked. Just ask |
| No | true | yes | Refused once. Explain, then ask again |
| No | false | **yes** | **Permanently refused.** Only Settings will change it |
| Yes | false | — | Granted |

Apps get this wrong constantly, and the symptom is a permission request that appears to do nothing
at all. On the device, the `USER_FIXED` flag in the `runtime permissions:` block records the
permanent refusal — so a tester can see the state directly even when the app cannot.

---

### 21. An app requests `BIND_ACCESSIBILITY_SERVICE`. Is that a finding?

Not on its own. Accessibility services are a legitimate and important feature, and reporting every
one as malicious is how a report loses credibility.

The finding is the **combination**:

- an app whose stated function has nothing to do with accessibility,
- which also requests `SYSTEM_ALERT_WINDOW`,
- and whose `res/xml/accessibility_service_config.xml` claims
  `canRetrieveWindowContent="true"` with `accessibilityEventTypes="typeAllMask"` and no package
  restriction.

Read that XML file. It is the accessibility service's real capability declaration, and it is **not
in the manifest** — the manifest only points at it.

The reason the combination matters: an accessibility service can read every window and inject
events, which means it can operate the permission dialogs themselves. **An accessibility service
defeats the runtime permission model entirely**, because that model's only control is a dialog. The
overlay permission is how malware guides a user through the multi-step Settings flow that enables
it in the first place.

Treat a granted `BIND_ACCESSIBILITY_SERVICE` as equivalent to holding every `dangerous` permission.

---

### 22. Is `QUERY_ALL_PACKAGES` a high-severity finding?

No. It is `normal` protection level, so any app that asks receives it silently at install.
**Measured**: Chrome holds it as `granted=true` on the test device.

Its presence tells you about the developer's intent, not about the platform's opinion of the app.
It is a privacy signal — package lists are an excellent fingerprint and an excellent targeting
signal — and it is a Play policy issue for published apps. It is not an escalation.

The far more informative artefact is the `<queries>` block, when present. That is a written list of
exactly which other apps this one wants to see. A list of root-manager package names is root
detection declared in XML. A list of banking apps inside a non-banking app is something worse. A
list of competitors is telemetry.

Read `<queries>`; mention `QUERY_ALL_PACKAGES` in a low-severity paragraph.

---

### 23. What is a `<permission-tree>`, and should I care?

It reserves a **namespace**. It creates no permission by itself. What it does is authorise the
declaring app to add permissions under that prefix at runtime, with
`PackageManager.addPermission(PermissionInfo)`.

You should care for exactly one reason: **an app with a permission tree has a permission surface
the manifest does not describe.** Permissions can appear after installation, with levels chosen in
code rather than in XML.

The platform constrains it usefully:

- The new name must be a strict sub-name of a tree the calling app declared.
- The calling app must own the tree.
- **The level can only be `normal` or `dangerous`.** A `signature` permission cannot be added
  dynamically — so anything a dynamically-added permission guards is, by construction, obtainable
  by an attacker.

A `<permission-tree>` in a manifest is a prompt to go looking in the DEX, not a finding:

```bash
grep -rn 'addPermission' jadx-out/
```

Note that this is invisible to every manifest-only tool, including this chapter's own
[permission-audit.py](scripts/permission-audit.py) — which is why that tool prints a dedicated
warning when it sees a tree rather than silently ignoring it.

---

### 24. What is the single fastest way to triage an app's permission posture?

Four commands, about ninety seconds.

```bash
# 1. what does it actually HOLD? (not what it asked for)
adb shell dumpsys package <pkg> > dump.txt
python3 scripts/grant-state.py dump.txt

# 2. which of its OWN permissions are enforceable?
adb shell pm list permissions -f -g > perms.txt
python3 scripts/permission-audit.py --manifest out/AndroidManifest.xml --pm-list perms.txt

# 3. the appop half, for anything flagged
adb shell cmd appops get <pkg>

# 4. the one grep that finds a permission granting itself
grep -n '<permission ' out/AndroidManifest.xml | grep -v protectionLevel
```

Then, and only then, the reachability work — from a probe app, never from the shell. See
[examples/probe-app/](examples/probe-app/).

---

## Related

- [README.md](README.md) — the full argument behind every answer here
- [cheatsheet.md](cheatsheet.md) — the same facts as lookup tables
- [mindmap.md](mindmap.md) — the whole chapter as one map
- [labs/lab-01-grant-state.md](labs/lab-01-grant-state.md) — questions 2, 6, 12, 13 as an exercise
- [labs/lab-02-squatting.md](labs/lab-02-squatting.md) — questions 7, 8, 9, 10, 19 as an experiment
- [labs/lab-03-confused-deputy.md](labs/lab-03-confused-deputy.md) — questions 15 and 18 in anger
- [21-App-Sandbox](../21-App-Sandbox/README.md) — where the GIDs in question 1 come from
- [27-ContentProviders](../27-ContentProviders/README.md) — what to do once the permission is yours
- [32-Manifest](../32-Manifest/README.md) — the declaration audit this FAQ deliberately does not repeat
