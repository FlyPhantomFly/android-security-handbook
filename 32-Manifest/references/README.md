# 32 — Manifest · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

The manifest is one of the better-documented parts of Android — the official element reference is
genuinely authoritative and worth reading end to end once. What it does *not* tell you is how the
defaults shift with `targetSdkVersion`, which is where the behaviour-changes pages come in.

---

## Official element reference

The primary source. Bookmark the index; the per-element pages are short and precise.

| Element | Page |
|---|---|
| Index | https://developer.android.com/guide/topics/manifest/manifest-intro |
| `<manifest>` | https://developer.android.com/guide/topics/manifest/manifest-element |
| `<application>` | https://developer.android.com/guide/topics/manifest/application-element |
| `<activity>` | https://developer.android.com/guide/topics/manifest/activity-element |
| `<activity-alias>` | https://developer.android.com/guide/topics/manifest/activity-alias-element |
| `<service>` | https://developer.android.com/guide/topics/manifest/service-element |
| `<receiver>` | https://developer.android.com/guide/topics/manifest/receiver-element |
| `<provider>` | https://developer.android.com/guide/topics/manifest/provider-element |
| `<grant-uri-permission>` | https://developer.android.com/guide/topics/manifest/grant-uri-permission-element |
| `<path-permission>` | https://developer.android.com/guide/topics/manifest/path-permission-element |
| `<intent-filter>` | https://developer.android.com/guide/topics/manifest/intent-filter-element |
| `<data>` | https://developer.android.com/guide/topics/manifest/data-element |
| `<permission>` | https://developer.android.com/guide/topics/manifest/permission-element |
| `<uses-permission>` | https://developer.android.com/guide/topics/manifest/uses-permission-element |
| `<uses-sdk>` | https://developer.android.com/guide/topics/manifest/uses-sdk-element |
| `<queries>` | https://developer.android.com/guide/topics/manifest/queries-element |
| `<meta-data>` | https://developer.android.com/guide/topics/manifest/meta-data-element |
| `<instrumentation>` | https://developer.android.com/guide/topics/manifest/instrumentation-element |

---

## The pages that explain the defaults

**This is the section that matters most**, because the element reference documents what an attribute
*does* while these pages document what happens when it is *absent*.

| Resource | Why |
|---|---|
| [Behaviour changes, all releases](https://developer.android.com/about/versions) | **The index to check before asserting any version-dependent behaviour.** Every claim in this chapter's Version Matrix traces back here |
| [`android:exported` requirement (API 31)](https://developer.android.com/about/versions/12/behavior-changes-12#exported) | Why the attribute became mandatory, and what happens to apps that omit it |
| [Package visibility (API 30)](https://developer.android.com/training/package-visibility) | Why your probe app cannot see the target without `<queries>` |
| [Cleartext traffic default (API 28)](https://developer.android.com/about/versions/pie/android-9.0-changes-28#framework-security-changes) | The default flip |
| [Scoped storage](https://developer.android.com/about/versions/11/privacy/storage) | `requestLegacyExternalStorage` and its expiry |
| [Foreground service types (API 34)](https://developer.android.com/about/versions/14/changes/fgs-types-required) | The `foregroundServiceType` requirement |
| [Runtime receiver export (API 33)](https://developer.android.com/about/versions/13/behavior-changes-13#runtime-receivers) | `RECEIVER_EXPORTED` / `RECEIVER_NOT_EXPORTED` |
| [PendingIntent mutability (API 31)](https://developer.android.com/about/versions/12/behavior-changes-12#pending-intent-mutability) | Why `FLAG_IMMUTABLE` became explicit |

---

## Security guidance

| Resource | Why |
|---|---|
| [App security best practices](https://developer.android.com/privacy-and-security/security-tips) | Google's own guidance; useful to hand to a developer alongside a finding |
| [Security guidelines — IPC](https://developer.android.com/privacy-and-security/security-tips#IPC) | The official position on exported components |
| [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider) | The `<paths>` configuration, including what `root-path` means |
| [Sharing files securely](https://developer.android.com/training/secure-file-sharing) | The intended FileProvider pattern |
| [Defining custom permissions](https://developer.android.com/guide/topics/permissions/defining) | And, implicitly, why a custom permission is only as strong as the app defining it |
| [App links verification](https://developer.android.com/training/app-links/verify-android-applinks) | `autoVerify` and `assetlinks.json` |
| [Data backup rules](https://developer.android.com/guide/topics/data/autobackup) | `allowBackup`, `fullBackupContent`, `dataExtractionRules` |

---

## Manifest merging

| Resource | Why |
|---|---|
| [Merge multiple manifest files](https://developer.android.com/build/manage-manifests) | **The merge rules, priority order, and every `tools:` marker.** Read this before auditing any app built from source |
| [Manifest merger report](https://developer.android.com/build/manage-manifests#inspect_the_merged_manifest_and_find_conflicts) | How to see what each library contributed |

> **Why this matters.** A third-party SDK can inject an exported component the app developer never
> wrote. Auditing the source manifest instead of the merged output misses it entirely. See
> [08-Build-System](../../08-Build-System/README.md) and
> [`labs/lab-05-merge-and-inject.md`](../labs/lab-05-merge-and-inject.md).

---

## AOSP source

Where the parsing and enforcement actually happen. Read on [cs.android.com](https://cs.android.com/).

| Path | Covers |
|---|---|
| `frameworks/base/services/core/java/com/android/server/pm/pkg/parsing/ParsingPackageUtils.java` | **The real manifest parser.** When a tool and the platform disagree, this is the arbiter |
| `frameworks/base/core/java/android/content/pm/parsing/ApkLiteParseUtils.java` | The lightweight parse done first at install |
| `frameworks/base/core/java/android/content/res/XmlBlock.java` | The AXML reader |
| `frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h` | The AXML structures themselves — see [10-APK-Internals](../../10-APK-Internals/README.md) |
| `frameworks/base/core/java/android/content/pm/ActivityInfo.java` | The parsed representation of `<activity>` |
| `frameworks/base/core/java/android/content/pm/ProviderInfo.java` | The parsed representation of `<provider>` |
| `frameworks/base/core/java/android/content/pm/PermissionInfo.java` | `protectionLevel` constants |
| `frameworks/base/core/java/android/content/IntentFilter.java` | The matching algorithm — action, categories, data |
| `frameworks/base/services/core/java/com/android/server/wm/ActivityStarter.java` | Where the export check actually rejects a launch |

---

## Tooling

| Tool | Use |
|---|---|
| [apktool](https://apktool.org/) | Decode AXML to readable XML |
| `aapt2 dump xmltree` | The parsed tree, independent of apktool |
| `aapt2 dump badging` | Package, SDK levels, permissions, launchable activity |
| `adb shell dumpsys package <pkg>` | **The authority** — what `PackageManager` actually parsed |
| [jadx](https://github.com/skylot/jadx) | Shows the manifest alongside the code |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Automated manifest analysis — validate its output, see [55-MobSF](../../55-MobSF/README.md) |
| [Drozer](https://github.com/WithSecureLabs/drozer) | Probing the exported surface from an app context |

### Chapter tooling

| File | Purpose |
|---|---|
| [`scripts/manifest-audit.py`](../scripts/manifest-audit.py) | Severity-rated audit that **applies the `targetSdk` matrix** — the same attribute means different things at different levels |
| [`scripts/frida-manifest-runtime.js`](../scripts/frida-manifest-runtime.js) | Reads what `PackageManager` parsed at runtime — the third leg of the three-way comparison |
| [`examples/vulnerable-manifest.xml`](../examples/vulnerable-manifest.xml) | 20+ planted issues |
| [`examples/vulnerable-manifest-ANSWERS.md`](../examples/vulnerable-manifest-ANSWERS.md) | The annotated answer key |
| [`examples/secure-manifest.xml`](../examples/secure-manifest.xml) | The same app, done correctly |
| [`examples/file_paths_insecure.xml`](../examples/file_paths_insecure.xml) / [`_secure`](../examples/file_paths_secure.xml) | FileProvider `<paths>`, wrong and right |

---

## OWASP

| Resource | Relevance |
|---|---|
| [MASVS-PLATFORM](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/) | The control category most manifest findings map to |
| [MASVS-CODE](https://mas.owasp.org/MASVS/10-MASVS-CODE/) | `debuggable`, `testOnly`, shipped instrumentation |
| [MASVS-STORAGE](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/) | `allowBackup` and backup rules |
| [MASTG](https://mas.owasp.org/MASTG/) | Test procedures; cite the IDs in reports |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [10-APK-Internals](../../10-APK-Internals/README.md) | AXML at byte level, and the parser-confusion technique |
| [08-Build-System](../../08-Build-System/README.md) | Manifest merging and how SDKs inject components |
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | How the parsed manifest becomes UID, permissions and components |
| [23-Permissions](../../23-Permissions/README.md) | `protectionLevel`, custom permissions, squatting |
| [24-IPC](../../24-IPC/README.md) | The wider IPC surface the manifest declares |
| [26-Intent](../../26-Intent/README.md) | Intent resolution, filters, and redirection |
| [27-ContentProviders](../../27-ContentProviders/README.md) | Provider attributes in depth, and FileProvider |
| [28-Services](../../28-Services/README.md) | `foregroundServiceType`, `isolatedProcess`, accessibility services |
| [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) | Runtime receivers, which the manifest cannot show you |
| [30-Activities](../../30-Activities/README.md) | `launchMode`, `taskAffinity`, task hijacking |
| [31-Fragments](../../31-Fragments/README.md) | **What the manifest cannot describe.** Fragments are not components, so a single exported Activity can host dozens of screens the audit never sees |
| [33-Storage](../../33-Storage/README.md) | `allowBackup` impact |
| [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) | The XML `networkSecurityConfig` points at |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Validating automated findings before reporting |
| [77-UsefulCommands](../../77-UsefulCommands/labs/lab-03-exported-sweep.md) | The reachability discipline — `adb shell` is not an app |
