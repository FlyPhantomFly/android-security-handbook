# 23 — Permissions · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure.

Two rules this file follows. **AOSP file paths are given without line numbers** — paths are stable
across releases, line numbers are not, and a citation that drifts is worse than no citation. And
**no CVE identifier is invented**: where a vulnerability class matters, the class is described and
you are told how to find the actual identifiers yourself.

---

## Primary source — AOSP

Pin the branch you are testing against before reading any of these. The permission model has grown
at almost every release, and reading `main` while testing an Android 12 device will mislead you
about at least the flag set.

```bash
# host — one file, from the branch you care about
# android.googlesource.com/platform/frameworks/base/+/refs/heads/android13-release/data/etc/platform.xml
```

### Where permissions are declared

| Path | Open it when |
|---|---|
| `frameworks/base/core/res/AndroidManifest.xml` | You need the **real `protectionLevel` of a platform permission**. This is where `android.permission.CAMERA` and every one of its siblings physically live. It is the file nobody looks at and the one that settles arguments |
| `frameworks/base/core/java/android/content/pm/PermissionInfo.java` | You need the `PROTECTION_*` and `PROTECTION_FLAG_*` constants, or the two masks (`PROTECTION_MASK_BASE = 0xf`, `PROTECTION_MASK_FLAGS = 0xfff0`). Read them from your branch rather than memorising them; the flag list grows |
| `frameworks/base/core/java/android/Manifest.java` | The generated constants apps compile against. Useful for confirming a permission exists at a given API level |

### The permission-to-GID mapping — this chapter's §3.5

| Path | Open it when |
|---|---|
| **`frameworks/base/data/etc/platform.xml`** | **The single most important file in this chapter.** Ships as `/system/etc/permissions/platform.xml`. Contains three element types that matter: `<permission><group gid="…"/></permission>` (permission → Linux group), `<assign-permission … uid="shell"/>` (permissions given to a **UID**, not a package — this is why `adb shell` is not an app), and `<split-permission>` (permissions an app receives without asking, based on its `targetSdk`) |
| `frameworks/base/core/java/com/android/server/SystemConfig.java` | You want to know *how* `platform.xml` is parsed, which other files in `etc/permissions/` are read, and in what order. Also where the privileged-app allow-lists are loaded |
| `system/core/libcutils/include/private/android_filesystem_config.h` | The AID table. `platform.xml` names groups (`inet`, `net_bt`); this file maps those names to numbers (3003, 3002). A vendor build can add names your reference table does not have |

> **🔬 Under the Hood**
> You do not need AOSP to read the mapping — the file is on the device and is world-readable:
> ```bash
> adb shell cat /system/etc/permissions/platform.xml
> adb shell ls /system/etc/permissions/ /vendor/etc/permissions/ /product/etc/permissions/
> ```
> The device's copy is authoritative for the device in front of you, and takes three seconds. The
> AOSP copy tells you what *should* be there, which is how you notice a vendor has changed it.

### Where the decision is made

| Path | Open it when |
|---|---|
| `frameworks/base/services/core/java/com/android/server/pm/permission/PermissionManagerServiceImpl.java` | The grant and revoke logic, and the supplementary-GID computation. This is the class named in the `SecurityException` you get from `pm grant` on a `normal` permission |
| `frameworks/base/services/core/java/com/android/server/pm/permission/PermissionManagerService.java` | The Binder-facing wrapper. Start here to trace an API call inwards |
| `frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java` | `checkComponentPermission` — the five-condition ladder that is the whole component access-control model. Root/system, same-UID, not-exported, null-permission, then the string compare, in that order |
| `frameworks/base/services/core/java/com/android/server/pm/PackageManagerShellCommand.java` | What `pm grant`, `pm revoke` and `pm list permissions` actually do, and why the first two refuse install-time permissions |

### Where the app-side call starts

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/app/ContextImpl.java` | The `check*Permission` / `enforce*Permission` family. Put `checkCallingPermission` and `checkCallingOrSelfPermission` side by side — the first tests `pid != Process.myPid()` and fails closed, the second does not. That single difference is a vulnerability class |
| `frameworks/base/core/java/android/content/ContextWrapper.java` | The pass-through your `Activity` or `Service` actually is. Where a Frida hook lands |
| `frameworks/base/core/java/android/app/Activity.java` | `requestPermissions` — note that it builds an `Intent` to another app rather than drawing anything, and that a second concurrent request is silently dropped |
| `frameworks/base/core/java/android/os/Binder.java` | `getCallingUid`, `getCallingPid`, `clearCallingIdentity`, `restoreCallingIdentity`. The UID here is the one the binder driver stamped into the transaction, and it is the only caller identity worth trusting |

### App Ops — the second state machine

| Path | Open it when |
|---|---|
| `frameworks/base/services/core/java/com/android/server/appop/AppOpsService.java` | You need to understand why a granted permission yields nothing. `MODE_IGNORED` returns empty data rather than throwing |
| `frameworks/base/core/java/android/app/AppOpsManager.java` | The op constants, the permission-to-op mapping, and the client API |

### The grant UI

| Path | Open it when |
|---|---|
| `packages/modules/Permission/` | The `PermissionController` module — the **separate, updatable app** that draws the runtime dialog. Read it when a device's prompt behaves differently from what the documentation describes, which on vendor builds it often does |

---

## Official documentation

| Resource | Why you would open it |
|---|---|
| Android developer guide — **Permissions on Android** | The model as the platform team frames it. Read it for the vocabulary, then read this chapter for what it omits — chiefly that `normal` is the default and what that means |
| Android developer guide — **Request runtime permissions** | The API 23+ flow: `requestPermissions`, `onRequestPermissionsResult`, rationale handling, one-time grants. The authority on the state machine in §3.7 |
| Android developer reference — **`<permission>`** and the `protectionLevel` attribute | The authoritative attribute and flag list for a given API level. Cross-check against `PermissionInfo.java`, because the documentation lags the source |
| Android developer reference — **`<uses-permission>`**, `<permission-group>`, `<permission-tree>` | `maxSdkVersion`, `usesPermissionFlags="neverForLocation"`, and the tree rules for `addPermission` |
| Android developer guide — **Package visibility filtering** | `<queries>` and `QUERY_ALL_PACKAGES`. Read it before you write a probe app, not after it silently returns nothing |
| Android developer guide — **App permissions best practices** | The developer-facing version of this chapter's remediation advice. Useful to quote back in a report, because clients act faster on Google's wording than on yours |
| Android developer guide — **Auto-reset permissions from unused apps** | The API 30 behaviour behind the `AUTO_REVOKED` flag |
| **Android Security Bulletins** | Where the confused-deputy class from §3.9 actually appears, month after month. Search by component and for the phrase describing a local escalation reachable with no additional execution privileges — that phrasing is the bulletin's way of saying "an ordinary app could reach this" |
| **Android Compatibility Definition Document (CDD)** | Section on permissions. What a device manufacturer is *required* to implement, which is the baseline a vendor build can deviate from. Useful when a device behaves unlike AOSP and you need to say whether that is permitted |

---

## OWASP

| Identifier | Relevance to this chapter |
|---|---|
| **MASVS-PRIVACY-1** | *"The app minimizes access to sensitive data and resources."* The chapter's primary control. A granted-but-unused permission is a direct failure, and the evidence is the granted list cross-referenced against DEX API usage. It is the most-failed and least-*reported* control in this area, because failing it is boring — report it anyway, in a low-severity section, because the fix is deleting three lines |
| **MASVS-PLATFORM-1** | *"The app uses IPC mechanisms securely."* Custom permission protection levels, exported components and the confused-deputy pattern land here |
| **MASVS-PLATFORM-3** | User-facing surfaces: overlay and accessibility abuse — §3.12 |
| **MASVS-CODE-4** | Manual review of the permission surface as part of secure development |
| **MASTG — Testing App Permissions** | The procedure §7 implements. Note what MASTG under-emphasises and this chapter does not: the separation of *requested* from *granted*, and the app-op half of `appop`-flagged permissions |
| **MASTG — Testing for Sensitive Functionality Exposure Through IPC** | The confused-deputy work in §3.9 and [lab-03](../labs/lab-03-confused-deputy.md) |

> **⚠️ Warning**
> Cite a MASVS control by identifier **and** by what you actually observed. "Fails MASVS-PRIVACY-1"
> on its own is unactionable; "requests `RECORD_AUDIO`, holds it, and no code path calls
> `AudioRecord` — MASVS-PRIVACY-1" is a fix. See [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md)
> for the full structure and for how not to overstate what a control ID means.

---

## Research

| Work | Why |
|---|---|
| **"Android Permissions Demystified"** — Felt, Chin, Hanna, Song, Wagner. ACM CCS 2011 | The original permission-to-API mapping, and the first quantification of over-privilege in real apps. The specific numbers are dated; the *method* — intersect what is requested with what the code calls — is exactly the analysis in §8.3, and is still how over-privilege is found |
| **"Permission Re-Delegation: Attacks and Defenses"** — Felt, Wang, Moshchuk, Hanna, Chin. USENIX Security 2011 | The original statement of the confused-deputy problem in precisely the form §3.9 describes. Read it for the framing: the attacker never obtains the permission, and the defence is not "check harder" but "check *whose* authority you are acting on" |
| **"Android Permissions: User Attention, Comprehension, and Behavior"** — Felt et al., SOUPS 2012 | The empirical basis for treating a `dangerous` permission dialog as a speed bump. Most users cannot correctly state what a permission they just granted allows |
| **"Analyzing Inter-Application Communication in Android"** — Chin, Felt, Greenwood, Wagner. MobiSys 2011 | The exported-component surface that permissions are supposed to guard. Pairs with [21-App-Sandbox](../../21-App-Sandbox/README.md) and [24-IPC](../../24-IPC/README.md) |

These are old papers about a platform that has changed a great deal. They remain accurate about the
**mechanisms** — which is the part that has not changed — and they are worth reading precisely
because they were written when the model was small enough to describe completely.

---

## Conference talks worth finding

Search by topic rather than by URL; recordings move.

- Android Security Bulletin retrospectives — any talk that walks a year of "elevation of privilege
  in a system component" entries is, in effect, a tour of the confused-deputy class.
- Talks on OEM pre-installed app auditing. The methodology in [lab-03](../labs/lab-03-confused-deputy.md)
  is the standard one, and hearing someone walk a real device is worth more than reading it.
- Anything on `PendingIntent` mutability. It is the permission-borrowing primitive that API 31 made
  explicit, and the talks predate that change, which is why they explain *why* it mattered.
- Banking-trojan teardowns, for the accessibility pivot. The permission-side lesson is in §5.8:
  an accessibility service can operate the permission dialogs, and therefore defeats the runtime
  permission model outright.

---

## Chapter tooling

| File | What it answers |
|---|---|
| [`../scripts/grant-state.py`](../scripts/grant-state.py) | From a `dumpsys package` capture: what does this app **hold**, and what is the gap between that and what it asked for? Prints the four sets, the GID list, the runtime flags, and flags every `appop` permission for which `dumpsys` alone is insufficient |
| [`../scripts/permission-audit.py`](../scripts/permission-audit.py) | Which of the app's **own** permissions are enforceable? One row per *population* that can obtain each permission, and — with a device capture — who owns the name. Verdicts: `SQUATTED`, `NOT-A-BOUNDARY`, `UNOWNED`, `UNRESOLVED`, `EXTERNAL`, `ENFORCEABLE` |
| [`../scripts/hook-permission-checks.js`](../scripts/hook-permission-checks.js) | At runtime: every permission the app asks about, every request and result, and a loud flag with a stack trace on every `checkCallingOrSelfPermission`. Observes by default; `--force` mode labels its own transcript as modified |
| [`../examples/squat-pair/`](../examples/squat-pair/) | Four manifests and a build script that reproduce permission squatting end to end, with three different signing keys |
| [`../examples/probe-app/`](../examples/probe-app/) | The unprivileged probe. `adb shell` is UID 2000; this is what proves reachability |
| [`../examples/SignatureGuardedService.java`](../examples/SignatureGuardedService.java) | The four-layer remediation, as code |
| [`../examples/weak-permissions-AndroidManifest.xml`](../examples/weak-permissions-AndroidManifest.xml) | An audit target with ten planted defects, one per element |

### External tooling

| Tool | Where | Use it for |
|---|---|---|
| `adb` / `dumpsys` / `pm` / `cmd appops` | Platform tools | Everything in §7. `dumpsys package permission <name>` is the one to memorise |
| `apktool` | github.com/iBotPeaches/Apktool | Decoding `AndroidManifest.xml` to readable XML |
| `aapt2 dump permissions` | Android SDK build-tools | The fastest permission list, straight from an APK — but it does **not** print `protectionLevel` |
| `jadx` | github.com/skylot/jadx | Finding the check sites. Permission strings cannot be obfuscated, so they are reliable anchors |
| Frida | frida.re | [53-Frida](../../53-Frida/README.md) for setup and version pinning |
| Drozer | Package-info and attack-surface modules. Does **not** resolve protection levels from the device — that is the gap this chapter's scripts fill |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | UID assignment, `packages.list`, and the supplementary-GID table. Chapter 09 owns *how a UID is assigned*; this chapter owns *what is granted on top of it* |
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | Where permissions sit among Android's overlapping defences |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | **The UID boundary that permissions punch holes in.** Its `manifest-exposure.py` prints `NOT-A-BOUNDARY` for a weak custom permission; §3.6 here is the measurement behind that verdict. It forward-references this chapter's §3.5 (GIDs), §3.9 (re-delegation), §3.11 (visibility) and §3.12 (special access) |
| [24-IPC](../../24-IPC/README.md) | The wider IPC surface that permissions guard |
| [27-ContentProviders](../../27-ContentProviders/README.md) | **Provider exploitation. This chapter owns the permission that guards it.** 27's own references say you cannot triage a provider without this chapter, and the reverse is also true — once the permission is yours, everything after that is 27's |
| [31-Fragments](../../31-Fragments/README.md) | There is no permission on a Fragment, and no `exported` attribute either. The host Activity's `android:permission` is the only gate, and 31 measures what happens when the app adds one of its own |
| [32-Manifest](../../32-Manifest/README.md) | **The declaration audit and the `targetSdk` version matrix.** 32 owns which attribute you write and what its default is; this chapter owns what is actually granted, by what mechanism, to whom. Run `manifest-audit.py` alongside this chapter's tools — they answer different questions |
| [34-Cryptography](../../34-Cryptography/README.md) | Why forging a signature match is not on the table, which is the precondition for `signature` being a boundary at all |
| [37-RootDetection](../../37-RootDetection/README.md) | `<queries>` blocks listing root-manager packages — root detection declared in XML |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What obfuscation does and does not reach. Permission strings are immune, which makes them the most reliable anchors in a stripped DEX |
| [53-Frida](../../53-Frida/README.md) | Setup and version pinning for `hook-permission-checks.js` |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | The MASVS structure, and how to cite a control without overstating it |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The reachability discipline: `adb shell` is not an app |
