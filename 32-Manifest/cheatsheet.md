# 32 — Manifest · Cheat Sheet

Printable. The manifest audit reference. See [README.md](README.md) for why each attribute matters.

---

## Read it three ways — always

```bash
# host — 1. apktool (decoded XML)
apktool d -f app.apk -o work/ && cat work/AndroidManifest.xml

# host — 2. aapt2 (the parsed tree)
aapt2 dump xmltree app.apk --file AndroidManifest.xml

# device — 3. THE AUTHORITY: what PackageManager actually parsed
adb shell dumpsys package com.example.target
```

If the three disagree, **the platform is right and the disagreement is the finding** — a crafted
AXML can make tools show one thing while `PackageManager` parses another.
See [10-APK-Internals](../10-APK-Internals/README.md).

```bash
# host — quick badging summary
aapt2 dump badging app.apk | grep -E '^(package|sdkVersion|targetSdkVersion|uses-permission|launchable)'
```

---

## THE FIRST THING TO CHECK: targetSdkVersion

The same attribute means different things at different levels. Read `targetSdk` before anything else.

| targetSdk | What it turns on |
|---|---|
| 17 | `<provider>` defaults to `exported="false"` |
| 23 | Runtime permission model |
| 24 | User-added CAs **no longer trusted** by default |
| 26 | Background execution + implicit broadcast limits |
| 28 | **Cleartext HTTP denied** by default |
| 29 | Scoped storage (with `requestLegacyExternalStorage` escape) |
| 30 | Scoped storage enforced; `<queries>` package visibility |
| 31 | **`android:exported` MANDATORY** on filtered components; **PendingIntent mutability explicit** |
| 33 | `RECEIVER_EXPORTED`/`NOT_EXPORTED` required for runtime receivers |
| 34 | `foregroundServiceType` required |

> A low `targetSdk` is itself a finding — it re-enables a whole set of legacy behaviours. Report it,
> then test each behaviour it re-enables.

---

## `<manifest>`

| Attribute | Audit note |
|---|---|
| `package` | The security principal. Identity is package + signing cert, not package alone |
| `sharedUserId` | **Deprecated.** Co-signed apps share one UID and one sandbox — expands blast radius |
| `android:versionCode` / `versionName` | Record both in the report |
| `installLocation` | `preferExternal` puts the APK on removable media |

---

## `<application>` — the highest-yield element

| Attribute | Safe | Finding when |
|---|---|---|
| `android:debuggable` | `false` | **`true` → CRITICAL.** `run-as` gives full private data access over USB; JDWP attachable |
| `android:allowBackup` | context | `true` + sensitive local data → `adb backup` / cloud exfiltration |
| `android:fullBackupContent` | — | Points to the include/exclude rules — read them |
| `android:dataExtractionRules` | — | The Android 12+ replacement; covers cloud backup **and** D2D transfer separately |
| `android:usesCleartextTraffic` | `false` | `true` permits plaintext HTTP regardless of targetSdk |
| `android:networkSecurityConfig` | present | Absent = defaults apply. Present = **read the XML** ([44](../44-NetworkSecurityConfig/README.md)) |
| `android:testOnly` | absent | Present in a shipped build = build hygiene finding |
| `android:extractNativeLibs` | — | `false` → `.so` mmap'd from the APK, not extracted to `lib/` |
| `android:requestLegacyExternalStorage` | absent | Opts out of scoped storage (≤ targetSdk 29) |
| `android:preserveLegacyExternalStorage` | absent | Extends the opt-out across an update |
| `android:hasFragileUserData` | — | Offers to keep data on uninstall |
| `android:allowClearUserData` | `true` | `false` prevents the user clearing data |
| `android:name` | — | **The `Application` class. An obscure name = likely packer stub** ([40](../40-Obfuscation/README.md)) |
| `android:appComponentFactory` | — | Can instantiate components — a code-injection surface |
| `android:largeHeap` | — | Raises heap cap; more secrets resident |
| `android:enableOnBackInvokedCallback` | — | Predictive back; not security-relevant |

---

## `<activity>` / `<activity-alias>`

| Attribute | Audit note |
|---|---|
| `android:exported` | Mandatory from targetSdk 31 when a filter is present. Below that, **a filter implies exported** |
| `android:permission` | The guard. Exported + no permission = your working list |
| `android:launchMode` | `singleTask` / `singleInstance` + `taskAffinity` → **task hijacking** ([30](../30-Activities/README.md)) |
| `android:taskAffinity` | Empty string (`""`) is the hardening; a shared affinity is the risk |
| `android:allowTaskReparenting` | `true` lets the activity move to another task |
| `android:excludeFromRecents` | Keeps a sensitive screen out of the recents thumbnail |
| `android:noHistory` | Activity not kept in the back stack |
| `android:clearTaskOnLaunch` / `finishOnTaskLaunch` | Task-stack behaviour |
| `android:autoRemoveFromRecents` | — |
| `android:directBootAware` | Runs before first unlock — check what it touches |
| `android:showWhenLocked` / `turnScreenOn` | Displays over the lockscreen |
| `android:documentLaunchMode` | Recents behaviour |
| `android:allowEmbedded` | Can be embedded in another activity's task |
| `android:resizeableActivity` | Multi-window |
| `android:windowSoftInputMode` | — |

`<activity-alias>` has its **own** `exported` and `permission`. An alias can expose a
non-exported target activity. Audit aliases separately.

---

## `<service>`

| Attribute | Audit note |
|---|---|
| `android:exported` | Exported service = an RPC entry point |
| `android:permission` | The guard |
| `android:isolatedProcess` | `true` = strongest sandbox available to an app ([21](../21-App-Sandbox/README.md)) |
| `android:foregroundServiceType` | Required from targetSdk 34; the type declares intent |
| `android:externalService` | Can be bound by apps in other users |
| `android:directBootAware` | — |

Watch for `BIND_ACCESSIBILITY_SERVICE` and `BIND_NOTIFICATION_LISTENER_SERVICE` — ultra-privileged
service types abused by banking trojans ([28](../28-Services/README.md)).

---

## `<receiver>`

| Attribute | Audit note |
|---|---|
| `android:exported` | Exported receiver accepts attacker-controlled intents |
| `android:permission` | Required sender permission |
| `android:directBootAware` | — |

Runtime-registered receivers need `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED` from targetSdk 33 —
**not visible in the manifest**. Find them in code ([29](../29-BroadcastReceivers/README.md)).

---

## `<provider>` — the richest surface

| Attribute | Audit note |
|---|---|
| `android:authorities` | The `content://` namespace. Must be unique device-wide |
| `android:exported` | Defaults to `false` from targetSdk 17 |
| `android:permission` | Blanket read+write guard |
| `android:readPermission` / `writePermission` | Finer-grained; override `permission` |
| `android:grantUriPermissions` | `true` → temporary grants possible → **URI-grant theft via intent redirection** |
| `android:multiprocess` | Instance per process |
| `android:initOrder` | Higher runs earlier — relevant to `androidx.startup` persistence |
| `android:syncable` | — |
| `android:directBootAware` | — |

### Child elements

| Element | Audit note |
|---|---|
| `<grant-uri-permission path/pathPrefix/pathPattern>` | Which URIs may be granted. `path="/"` grants everything |
| `<path-permission>` | **Subtle and frequently misused.** Per-path permissions that can *narrow* or *widen* access. Read carefully — a missing path leaves the provider's blanket permission in effect |

### FileProvider `<paths>`

| Element | Maps to |
|---|---|
| `<files-path>` | `getFilesDir()` |
| `<cache-path>` | `getCacheDir()` |
| `<external-path>` | `Environment.getExternalStorageDirectory()` |
| `<external-files-path>` | `getExternalFilesDir()` |
| `<external-cache-path>` | `getExternalCacheDir()` |
| `<root-path>` | **The filesystem root.** `<root-path name="r" path="." />` exposes everything readable by the app |

---

## `<intent-filter>`

| Attribute | Audit note |
|---|---|
| `android:priority` | Higher wins for ordered broadcasts → **interception** |
| `android:autoVerify` | App Links verification via `assetlinks.json` |
| `android:order` | Ordering among matching filters |

Matching rule: **action must match**, **ALL categories must be present**, data matched on
scheme/host/port/path. `CATEGORY_DEFAULT` is **required** for an implicit intent to reach an activity.

```bash
# adb shell — fire a deep link
am start -a android.intent.action.VIEW -d "myapp://path?x=1"
```

---

## Permissions

| Element | Audit note |
|---|---|
| `<uses-permission>` | Map each to what an attacker gains if the app is compromised |
| `android:maxSdkVersion` | Permission only requested up to that level — easy to miss |
| `<uses-permission-sdk-23>` | Only requested from API 23 |
| `<permission>` | **Custom permission.** Only as strong as the app defining it |
| `<permission-group>` / `<permission-tree>` | — |

### protectionLevel

| Value | Meaning |
|---|---|
| `normal` | Auto-granted |
| `dangerous` | Runtime prompt |
| `signature` | Same signing key only |
| `signatureOrSystem` | Deprecated |
| `|privileged` | Privileged apps |
| `|appop` | Backed by AppOps |
| `|development` | Grantable via `pm grant` |
| `|instant` | Instant apps |
| `|role` | Role-based |
| `|knownSigner` | Named signers |

**Custom permission squatting**: a malicious app installed *first* can define a custom permission
with a weaker `protectionLevel`, and the first definition wins ([23](../23-Permissions/README.md)).

### Special permissions worth flagging

`SYSTEM_ALERT_WINDOW` · `MANAGE_EXTERNAL_STORAGE` · `PACKAGE_USAGE_STATS` · `REQUEST_INSTALL_PACKAGES`
· `QUERY_ALL_PACKAGES` · `BIND_ACCESSIBILITY_SERVICE` · `BIND_DEVICE_ADMIN`

---

## Other elements

| Element | Audit note |
|---|---|
| `<queries>` | Package visibility from targetSdk 30 |
| `<uses-library>` / `<uses-native-library>` | Shared library dependencies |
| `<uses-feature>` | Hardware requirements |
| `<meta-data>` | **API keys hide here.** Grep every value |
| `<profileable>` | Profiling permitted |
| `<instrumentation>` | **A shipped `<instrumentation>` tag is a finding** — test code in production |
| `<supports-screens>` / `<uses-configuration>` | Not security-relevant |

---

## Manifest merging

Library manifests are merged into the app's. **An SDK can inject an exported component the app
developer never wrote.**

```bash
# host — the merged result, per build variant
find . -path '*/build/intermediates/merged_manifest*' -name AndroidManifest.xml
cat app/build/outputs/logs/manifest-merger-*-report.txt
```

| `tools:` marker | Effect |
|---|---|
| `tools:node="merge"` | Default |
| `tools:node="replace"` | Replace the lower-priority element |
| `tools:node="remove"` | Remove it |
| `tools:node="removeAll"` | Remove all matching |
| `tools:replace="attr"` | Replace named attributes |
| `tools:remove="attr"` | Remove named attributes |

**Audit the MERGED manifest, not the source.** They differ. See
[08-Build-System](../08-Build-System/README.md).

---

## Audit commands

```bash
# host — exported components with no permission (the working list)
grep -oE '<(activity|activity-alias|service|receiver|provider)[^>]*' work/AndroidManifest.xml \
  | grep 'exported="true"' | grep -v 'android:permission'

# host — every provider authority
grep -oE 'android:authorities="[^"]*"' work/AndroidManifest.xml

# host — meta-data values (API keys hide here)
grep -oE '<meta-data[^>]*' work/AndroidManifest.xml

# host — the flags that matter, in one pass
grep -oE 'android:(debuggable|allowBackup|usesCleartextTraffic|testOnly|sharedUserId|networkSecurityConfig)="[^"]*"' \
  work/AndroidManifest.xml

# device — what the platform ACTUALLY parsed
adb shell dumpsys package com.example.target | grep -E 'flags=|privateFlags=|targetSdk|versionCode'
adb shell dumpsys package com.example.target | grep -n 'exported=true'
```

### Automated

```bash
python3 scripts/manifest-audit.py work/AndroidManifest.xml
python3 scripts/manifest-audit.py app.apk --target-sdk 31
frida -U -f com.example.target -l scripts/frida-manifest-runtime.js
```

---

## THE DISCIPLINE

**A component reachable from `adb shell` is NOT proven reachable by an attacker.**

`adb shell` runs as UID 2000 (`shell`) and holds privileges an app does not. Reproduce from an
unprivileged app before reporting. See [labs/lab-03-proving-reachability.md](labs/lab-03-proving-reachability.md)
and [77-UsefulCommands](../77-UsefulCommands/labs/lab-03-exported-sweep.md).

---

## Severity quick guide

| Finding | Typical |
|---|---|
| `debuggable="true"` in production | **High** |
| Signed with public debug key | **High** |
| Exported component performing a sensitive action, no permission | **High** |
| Provider exported with no read permission, exposing PII | **High** |
| `root-path` FileProvider | **High** |
| `allowBackup="true"` + local credentials | **Medium** |
| Low `targetSdk` re-enabling legacy defaults | **Medium** |
| `usesCleartextTraffic="true"` | Medium (context) |
| Over-broad `<grant-uri-permission path="/">` | Medium |
| Shipped `<instrumentation>` tag | Low–Medium |
| Over-permissioning with no demonstrated impact | Low–Info |

---

## Rules

1. Read `targetSdk` **first** — it changes what every other attribute means.
2. Read the manifest **three ways**; the platform is authoritative.
3. Audit the **merged** manifest, not the source.
4. `<activity-alias>` has its own export state.
5. `<path-permission>` can widen as well as narrow.
6. `root-path` in a FileProvider is almost always wrong.
7. `<meta-data>` is where API keys hide.
8. A filter without explicit `exported` means **exported** below targetSdk 31.
9. `adb shell` reachability is not proof.
10. Runtime-registered receivers are invisible here — find them in code.
