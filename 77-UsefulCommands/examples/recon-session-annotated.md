# Annotated recon session — the first 60 minutes

A complete device-and-app reconnaissance pass, annotated line by line.

**How to read this.** Every block shows the command, then representative output, then what that
output actually tells you. The output is *representative*, not captured from any specific device —
version strings, package names and hashes will differ on yours. What does not differ is the shape of
the output and the reasoning applied to it, which is the point.

The target throughout is a fictional `com.example.vault` on a test device.

> **Everything here is read-only** except where explicitly flagged **[MUTATES]**. Run this pass
> before you change anything, so you have a baseline to compare against.

---

## Phase 0 — Establish and record the session

```bash
adb devices -l
```

```
List of devices attached
39041FDJH00LKM         device usb:1-2 product:redfin model:Pixel_5 device:redfin transport_id:3
```

`device` is the state you want. `unauthorized` means the RSA prompt was never accepted;
`offline` usually means the daemon is wedged (`adb kill-server` and retry). The `transport_id` is
worth noting — with two devices attached, `adb -t 3 shell` is unambiguous where `-s` on a duplicated
serial is not.

```bash
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.vendor.build.security_patch
```

```
google/redfin/redfin:13/TQ3A.230805.001/10316531:user/release-keys
13
33
2023-08-05
2023-07-01
```

Five properties, and each one changes how you interpret later findings:

- **The fingerprint** encodes brand, device, release, build ID and **build type**. `user` is a
  production build; `userdebug` or `eng` grants privileges no production device has, which would
  invalidate most findings.
- **`release-keys`** means signed with the OEM's production keys. `test-keys` means it is not a
  stock build, and anything you conclude about platform integrity is void.
- **SDK 33** determines the default behaviours. `android:exported` has been mandatory since 31;
  runtime receivers need an explicit export flag since 33. See
  [32-Manifest](../../32-Manifest/README.md).
- **Two patch levels.** The framework patch level and the vendor patch level diverge routinely, and
  the vendor one is usually older. Record both — a report that cites only the first is incomplete.

```bash
adb shell getprop ro.debuggable
adb shell getprop ro.secure
adb shell id
```

```
0
1
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),...
```

`ro.debuggable=0` and `ro.secure=1` confirm a production-shaped build.

**The `id` output is the most important line in this document.** You are UID 2000 — the `shell`
user. You hold `groups` a third-party app never holds, and a set of permissions granted through
`platform.xml`. Anything you reach from here you have reached *as `shell`*, not *as an app*. Every
component finding has to be re-proven from an unprivileged app before it can be reported. See
[`../labs/lab-03-exported-sweep.md`](../labs/lab-03-exported-sweep.md).

---

## Phase 1 — Locate the target

```bash
adb shell pm list packages -3 | sort
```

```
package:com.example.vault
package:com.example.othertool
...
```

`-3` restricts to third-party packages, which is nearly always what you want; without it you get
several hundred system packages. Other flags worth knowing: `-s` system only, `-d` disabled only,
`-e` enabled only, `-u` include uninstalled-but-retained, `-f` show the APK path.

```bash
adb shell pm path com.example.vault
```

```
package:/data/app/~~kQ8f.../com.example.vault-Vd9j.../base.apk
package:/data/app/~~kQ8f.../com.example.vault-Vd9j.../split_config.arm64_v8a.apk
```

**Two lines, not one.** This app ships split APKs. A triage script that pulls only `base.apk` will
miss whatever lives in the splits — native libraries here, but density and language splits also
carry resources. Pull all of them.

The `~~kQ8f...` component is randomised per install since Android 11; do not hard-code it.

```bash
adb pull /data/app/~~kQ8f.../com.example.vault-Vd9j.../base.apk ./vault-base.apk
```

---

## Phase 2 — What the platform parsed

This is the authority. Tools decode the manifest; `dumpsys` reports what `PackageManager` actually
*accepted*, and the two can disagree.

```bash
adb shell dumpsys package com.example.vault > dumpsys-vault.txt
wc -l dumpsys-vault.txt
```

```
612 dumpsys-vault.txt
```

Save it to a file. It is long, you will read it several times, and it is evidence.

```bash
grep -E 'versionName|versionCode|targetSdk|minSdk|firstInstallTime|flags' dumpsys-vault.txt
```

```
    versionCode=1420 minSdk=26 targetSdk=33
    versionName=4.2.0
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
    firstInstallTime=2024-03-11 09:22:14
```

`ALLOW_BACKUP` in `flags` is a live finding candidate: `adb backup` may extract app data. Confirm it
rather than assuming — the flag is necessary but not sufficient, because `dataExtractionRules` and
`fullBackupContent` can still exclude everything meaningful. See
[33-Storage](../../33-Storage/README.md).

Note `HAS_CODE`. Its absence would mean a resource-only package, which changes the whole approach.

```bash
grep -A2 'signatures' dumpsys-vault.txt
adb shell dumpsys package com.example.vault | grep -E 'signing|Signature'
```

Cross-check against the APK itself:

```bash
apksigner verify --print-certs --verbose vault-base.apk
```

```
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v4 scheme (APK Signature Scheme v4): false
Signer #1 certificate DN: CN=Example Corp, O=Example, C=GB
Signer #1 certificate SHA-256 digest: 3a7f...c21e
```

v2+v3 with v1 absent is the modern, correct configuration — v1 (JAR) signing is the one vulnerable
to the Janus class of issue on old platforms. Record the SHA-256 digest: it is how you later prove a
repackaged sample is *not* the original. See [10-APK-Internals](../../10-APK-Internals/README.md).

---

## Phase 3 — The exported surface

```bash
adb shell dumpsys package com.example.vault | sed -n '/^  Activity Resolver Table/,/^  Key Set Manager/p'
```

This section lists components reachable through intent resolution. What it does **not** cleanly
separate is exported-vs-not, so pair it with the manifest:

```bash
apktool d -f -o vault-src vault-base.apk
grep -nE 'android:exported="true"' vault-src/AndroidManifest.xml
```

```
23:        <activity android:name=".ui.MainActivity" android:exported="true">
41:        <activity android:name=".ui.DeepLinkActivity" android:exported="true">
58:        <provider android:name=".data.VaultProvider" android:authorities="com.example.vault.files" android:exported="true">
```

Three exported components. Now the discipline: **each one needs its protection checked, not just its
export flag.**

```bash
grep -n -A6 'VaultProvider' vault-src/AndroidManifest.xml
```

```
58:        <provider android:name=".data.VaultProvider"
59:            android:authorities="com.example.vault.files"
60:            android:exported="true"
61:            android:grantUriPermissions="true">
62:            <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
63:                android:resource="@xml/file_paths" />
64:        </provider>
```

Exported, no `android:permission`, `grantUriPermissions="true"`. That is worth pursuing. Read the
paths configuration before touching the device:

```bash
cat vault-src/res/xml/file_paths.xml
```

```xml
<paths>
    <root-path name="root" path="/" />
</paths>
```

`<root-path path="/">` is the FileProvider misconfiguration — it exposes the entire filesystem
readable by the app's UID, not just a designated share directory. Confirm reachability before
reporting, and confirm it **from an app**, not from `shell`. See
[27-ContentProviders](../../27-ContentProviders/README.md).

---

## Phase 4 — Storage baseline

```bash
adb shell run-as com.example.vault ls -laR /data/data/com.example.vault 2>/dev/null | head -40
```

`run-as` works only if the app is `debuggable`. On a production build it fails:

```
run-as: package not debuggable: com.example.vault
```

That failure is itself information: the app is not debuggable, so `run-as` is not a path in and the
private data directory needs root or a backup to reach.

With root:

<!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the comment below quotes the broken form to explain why the real command is quoted; the command itself is correct -->
```bash
# Note the OUTER quotes on every `su -c` below. `adb shell` joins its arguments
# with spaces before the device sees them, so `adb shell su -c 'a; b'` arrives as
# `su -c a; b` and only `a` runs as root.
adb shell "su -c 'ls -la /data/data/com.example.vault/{shared_prefs,databases,files}'"
```

```
/data/data/com.example.vault/shared_prefs:
-rw-rw---- u0_a218 u0_a218   412 2024-03-11 09:24 VaultPrefs.xml
/data/data/com.example.vault/databases:
-rw-rw---- u0_a218 u0_a218 32768 2024-03-11 09:25 vault.db
```

Note the UID (`u0_a218`) and the mode. `-rw-rw----` with no world bits is correct; a world-readable
file here would be a finding on its own. The `u0_a218` maps to the app's assigned UID —
see [21-App-Sandbox](../../21-App-Sandbox/README.md).

**Take a hash baseline now**, so you can diff after exercising the app:

```bash
adb shell "su -c 'find /data/data/com.example.vault -type f -exec sha256sum {} \;'" > baseline.txt
```

[`../labs/lab-04-storage-diff.md`](../labs/lab-04-storage-diff.md) builds on exactly this.

---

## Phase 5 — Runtime posture

```bash
adb shell ps -A | grep vault
```

```
u0_a218  12043  1289 15234560 187432 0  0 S com.example.vault
```

One process. A `:remote` or `:isolated` suffix on a second line would mean multiple processes, which
matters because each has its own memory space and possibly its own sandbox — and an
`android:isolatedProcess` service has almost no privileges at all.

```bash
adb shell cat /proc/12043/status | grep -E 'Uid|Gid|Groups|Seccomp|NoNewPrivs'
```

```
Uid:	10218	10218	10218	10218
Gid:	10218	10218	10218	10218
Groups:	3003 9997 20218 50218
Seccomp:	2
NoNewPrivs:	1
```

This is the sandbox, as built by `SpecializeCommon()` at fork time. `Seccomp: 2` is filter mode,
`NoNewPrivs: 1` means privileges can never be regained. Group `3003` is `inet` — the app has network
access. See [06-Android-Architecture](../../06-Android-Architecture/README.md) for how each of these
was set.

```bash
adb shell cat /proc/12043/attr/current
```

```
u:r:untrusted_app:s0:c218,c256,c512,c768
```

The SELinux context. `untrusted_app` is the normal third-party domain; the categories (`c218,...`)
are the per-app MLS categories that keep two apps apart even at the same domain. See
[22-SELinux](../../22-SELinux/README.md).

---

## Phase 6 — Network listeners

Frequently skipped, frequently productive.

```bash
adb shell "su -c 'ss -tlnp'" 2>/dev/null || adb shell "su -c 'netstat -tlnp'"
```

```
State  Local Address:Port   Peer Address:Port  Process
LISTEN 127.0.0.1:8081       0.0.0.0:*          users:(("m.example.vault",pid=12043,fd=42))
```

A localhost listener inside the app process. Any other app on the device can connect to it —
localhost is not a security boundary on Android. What it speaks, and whether it authenticates, is
now a question worth answering. See [24-IPC](../../24-IPC/README.md).

And the surface with no filesystem permissions at all:

```bash
adb shell "su -c 'cat /proc/net/unix'" | grep -i vault
```

```
0000000000000000: 00000002 00000000 00010000 0001 01 45231 @com.example.vault/ipc
```

The leading `@` marks the **abstract namespace**. Abstract sockets have no filesystem path, so no
file permissions apply — any app that knows the name can connect. This is one of the most reliably
overlooked pieces of IPC surface on Android.

---

## What you have after 60 minutes

| Question | Answer from above |
|---|---|
| Is this a production build? | Yes — `user`/`release-keys`, `ro.debuggable=0` |
| Both patch levels? | Framework 2023-08-05, vendor 2023-07-01 |
| Where is the code? | base + arm64 split — pull both |
| Signing scheme? | v2+v3, no v1; cert digest recorded |
| Exported surface? | 2 activities, 1 provider — provider unprotected |
| Obvious misconfiguration? | FileProvider `<root-path path="/">`, `ALLOW_BACKUP` |
| Storage baseline? | Hashed to `baseline.txt` |
| Sandbox posture? | seccomp on, `untrusted_app`, has `inet` |
| Extra IPC? | localhost:8081 and an abstract socket |

Two candidate findings, both needing app-context confirmation before they are findings at all.

> **The discipline that makes this a report rather than a list.** Nothing above has been proven
> exploitable. `shell` reached the provider; an app might not. The next step is
> [`../labs/lab-03-exported-sweep.md`](../labs/lab-03-exported-sweep.md) — rebuild each reach from an
> unprivileged app, and drop whatever does not survive.
