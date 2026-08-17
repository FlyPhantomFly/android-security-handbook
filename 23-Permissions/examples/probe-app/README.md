# The unprivileged probe

The single most common defect in a mobile permissions finding is that reachability was
demonstrated from `adb shell`.

`adb shell` runs as **UID 2000**, in the `shell` SELinux domain, and the platform hands that UID
permissions by policy that no installed package could ever request. On the test device,
`/system/etc/permissions/platform.xml` contains, verbatim:

```xml
<assign-permission name="android.permission.INTERNET" uid="shell" />
```

So `adb shell am start`, `adb shell content query` and `adb shell service call` establish a
**reachability upper bound**. They tell you what a privileged local user can do. They tell you
nothing about what an attacker's app can do.

This app is a plain third-party app with an ordinary UID and no permissions at all. **Anything it
reaches, an attacker's app reaches.**

## Files

| File | What it is |
|---|---|
| [ProbeActivity.java](ProbeActivity.java) | One activity, five probes, driven entirely from `am start` extras |
| [AndroidManifest.xml](AndroidManifest.xml) | No permissions, a `<queries>` block **you must edit**, and comments explaining all three deliberate choices |
| [build-probe.sh](build-probe.sh) | `javac` → `d8` → `aapt2` → `zipalign` → `apksigner`. No Gradle, no Android Studio, no network |

## Build and install

```bash
# host
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
./build-probe.sh
adb install -r out/probe-app.apk
```

> **⚠️ Edit `<queries>` first.**
> From `targetSdkVersion` 30 an app cannot see a package it has not declared an interest in. A
> probe that cannot see the target fails in ways that look exactly like a permission denial —
> `ActivityNotFoundException`, a null resolver result, an empty package list. Add your target to
> the `<queries>` block and rebuild, or you will report a false negative.

## The five probes

```bash
# host — can I read this provider?
adb shell am start -n com.probe.unprivileged/.ProbeActivity \
    --es probe query --es target 'content://com.target.app.provider/items'

# host — can I reach its call() RPC surface?
adb shell am start -n com.probe.unprivileged/.ProbeActivity \
    --es probe call --es target 'content://com.target.app.provider' --es method 'getConfig'

# host — can I start this activity? Extra --es values are forwarded to it.
adb shell am start -n com.probe.unprivileged/.ProbeActivity \
    --es probe activity --es target 'com.target.app/.DeepLinkActivity' \
    --es url 'https://example.invalid/'

# host — can I bind this service?
adb shell am start -n com.probe.unprivileged/.ProbeActivity \
    --es probe service --es target 'com.target.app/.SyncService'

# host — does THIS app hold a permission?
adb shell am start -n com.probe.unprivileged/.ProbeActivity \
    --es probe perm --es target 'android.permission.CAMERA'
```

Read the results with:

```bash
adb logcat -c    # before
adb logcat -d -s PROBE:V
```

## Measured output

Both of these were produced by exactly this app, built with exactly this script, on a physical
device running Android 13 / API 33.

**Probe `perm`, against a permission the app does not request:**

```text
I PROBE  : ================================================================
I PROBE  :   unprivileged probe
I PROBE  :   package = com.probe.unprivileged
I PROBE  :   uid     = 10146   (adb shell is 2000)
I PROBE  :   pid     = 20054
I PROBE  :   sdk     = 33
I PROBE  :   Anything this app can reach, an attacker's app can reach.
I PROBE  : ================================================================
I PROBE  : probe=perm target=android.permission.INTERNET
I PROBE  : RESULT: checkSelfPermission(android.permission.INTERNET) = -1  DENIED
```

That is the whole point of the app in one line. `adb shell` holds `INTERNET` by platform policy.
This app does not, because it did not ask for it, and it is therefore a truthful stand-in for an
attacker who has not asked for it either.

**Probe `query`, against a guarded system provider:**

```text
I PROBE  : probe=query target=content://com.android.contacts/contacts
W PROBE  : RESULT: query threw java.lang.SecurityException
W PROBE  :   message: Permission Denial: opening provider
           com.android.providers.contacts.ContactsProvider2 from
           ProcessRecord{1ba6f8b 20054:com.probe.unprivileged/u0a146} (pid=20054, uid=10146)
           requires android.permission.READ_CONTACTS or android.permission.WRITE_CONTACTS
W PROBE  :   -> DENIED by a permission check. Read the message for the permission name, then
           resolve its level: adb shell pm list permissions -f -g | grep -A4 <name>
```

Note what the denial message gives you for free: the fully-qualified provider class, the calling
UID, and **both** permission names — read and write. That is the start of the next test, not the
end of this one.

## Reading the result correctly

The exception **type** is the finding. These three are routinely conflated and they mean
completely different things:

| Outcome | What it means | Next step |
|---|---|---|
| `SecurityException: Permission Denial ... requires X` | The gate refused you. The component exists and is reachable *by someone* | Resolve `X`'s level and owner. If it is `normal`, request it and try again |
| `SecurityException: ... not exported from uid ...` | Not reachable cross-UID at all | Move on |
| `IllegalArgumentException: Unknown URI` | **You got through the gate.** The provider's own code rejected your path | Path enumeration. See [27-ContentProviders](../../../27-ContentProviders/README.md) |
| `ActivityNotFoundException` | Either not exported, or **your probe cannot see the package** | Check `<queries>` before concluding anything |
| A `Cursor` with rows | Reachable, and it returns data | Now assess whether the data matters |
| A `null` Cursor | Reachable; the provider chose to return nothing | Not a denial. Try other paths |

## The report sentence

Once you have both results, the finding writes itself:

> The component is reachable from an unprivileged application. Demonstrated with a purpose-built
> probe application (`com.probe.unprivileged`, UID 10146, holding no permissions and signed with an
> unrelated key), not from `adb shell`, which runs as UID 2000 and holds permissions assigned by
> platform policy that no installable application can request.

That parenthesis is what makes the claim defensible.

## Related

- [../../README.md](../../README.md) §3.8, §5.7, §7.5
- [../squat-pair/](../squat-pair/) — the permission whose grant this probe would exercise
- [../../labs/lab-03-confused-deputy.md](../../labs/lab-03-confused-deputy.md) — where the probe earns its keep
- [21-App-Sandbox](../../../21-App-Sandbox/README.md) — `manifest-exposure.py`, whose every `WIDENED` verdict says "re-test from a probe app"
- [32-Manifest](../../../32-Manifest/README.md) — `manifest-audit.py`, which marks every reachability-dependent finding `UNPROVEN` for the same reason
