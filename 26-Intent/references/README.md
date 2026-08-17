# 26 — Intent · References

Annotated. Each entry says what it is *for*, because a bare link list is a
bookmark bar, not a reference.

---

## 1. AOSP source — the primary sources

Paths below are from the AOSP tree and are stable across releases; **line numbers
are deliberately never given**, because they are not. Browse at
`https://cs.android.com/android/platform/superproject/main` or in a local
`repo`-synced tree.

| Path | Why you open it |
|---|---|
| `frameworks/base/core/java/android/content/Intent.java` | The message object itself. Every field, every flag constant with its hex value, `fillIn()` (the `PendingIntent` merge rule), `parseUri()`/`toUri()` (the `intent:` grammar), `prepareToLeaveProcess()` (the client-side `file://` check), `migrateExtraStreamToClipData()`. If you only ever read one file from this chapter, read this one. |
| `frameworks/base/core/java/android/content/IntentFilter.java` | **The matching algorithm.** `match()`, `matchAction()`, `matchCategories()`, `matchData()`, `findMimeType()`, and the `MATCH_CATEGORY_*` / `NO_MATCH_*` constants whose values §3.6 decodes. `matchCategories` iterates the *Intent's* categories — that five-line loop is the whole of the direction rule people get wrong. |
| `frameworks/base/core/java/android/content/IntentSender.java` | The base class `PendingIntent` extends; the `send()` plumbing and `SendIntentException`. |
| `frameworks/base/core/java/android/app/PendingIntent.java` | Creation, the flag constants, `getCreatorPackage()`/`getCreatorUid()` — the one system-stamped identity primitive on the Intent path. |
| `frameworks/base/services/core/java/com/android/server/IntentResolver.java` | The bucketed filter index: `mActionToFilter`, `mTypedActionToFilter`, `mTypeToFilter`, `mBaseTypeToFilter`, `mWildTypeToFilter`, `mSchemeToFilter`. These are exactly the headings `dumpsys package` prints, which is why reading this file makes the dump legible. |
| `frameworks/base/services/core/java/com/android/server/pm/ComputerEngine.java` | Modern `queryIntentActivitiesInternal` / `resolveIntent`, including package-visibility filtering. |
| `frameworks/base/services/core/java/com/android/server/wm/ActivityStarter.java` | Where the **security** decision is made, against `Binder.getCallingUid()`. The export check is a UID comparison; the two `SecurityException` messages you spend your life reading in logcat are thrown here. |
| `frameworks/base/services/core/java/com/android/server/wm/ActivityTaskManagerService.java` | The Binder entry point for `startActivity` and friends. |
| `frameworks/base/services/core/java/com/android/server/am/BroadcastQueue.java` | Broadcast delivery, ordering and `abortBroadcast`. Broadcast *resolution* is the same algorithm as everything else; delivery policy is here. |
| `frameworks/base/services/core/java/com/android/server/pm/verify/domain/` | `DomainVerificationService` and friends — App Links verification from API 31. The `pm get-app-links` state you measure in lab 03 is held here. |
| `frameworks/base/core/java/android/app/Instrumentation.java` | `execStartActivity` — the last code that runs in *your* process before the Binder hop. |
| `frameworks/base/core/java/android/os/BaseBundle.java`, `Bundle.java` | Lazy unparcelling of extras: why a malformed extra crashes inside `getStringExtra` rather than at delivery. |
| `frameworks/base/core/java/android/content/ContextWrapper.java`, `ContextImpl.java` | `startActivity`, `startService` (and `validateServiceIntent`, the client-side "must be explicit" check), `sendBroadcast`, `registerReceiver`. |

**Searching the tree:** the class names above never change, but the *packages* do —
`PendingIntentRecord` in particular has moved between `com.android.server.am` and
neighbouring packages across releases. Search by class name, not by path.

---

## 2. Official Android documentation

| Document | What to take from it |
|---|---|
| *Intents and Intent Filters* (developer.android.com guide) | The canonical statement of the three matching tests. Its "Intent resolution" subsection is short and correct; its examples under-state the `<data>` cross-product behaviour, which is why §3.4 measures it instead. |
| *Verify Android App Links* | The `assetlinks.json` format, the `autoVerify` attribute, and the Digital Asset Links relationship. Read alongside lab 03, which measures the state the guide describes producing. |
| *Handling Android App Links* | The developer-side workflow, including the Play App Signing fingerprint trap that causes most verification failures. |
| *Android 12 behavior changes — Pending intent mutability* | The API 31 mandate, stated by the platform. Pairs with §3.9 and the `--target-sdk 31` experiment in lab 04. |
| *Android 14 behavior changes — Safer intents* | The `targetSdk` 34 restrictions: implicit Intents may not reach non-exported components, and mutable `PendingIntent`s wrapping implicit Intents are constrained. |
| *Android 11 behavior changes — Package visibility* | Why `<queries>` exists, and why your `adb shell` view is wider than the app's (§7.7). |
| *App security best practices — Use intents to defer permissions* / *Security tips* | Google's own guidance on `setPackage`, explicit components and validating received Intents. Short; worth quoting back to a developer verbatim. |
| *`am` (Activity Manager) in the ADB shell command reference* | The full `<INTENT>` grammar. Also printed by the device: `adb shell am` with no arguments, which is the version that is actually true for the platform in front of you. |
| Digital Asset Links protocol specification | The statement format behind `assetlinks.json`, including `delegate_permission/common.handle_all_urls`. |

---

## 3. OWASP

| Identifier | Relevance |
|---|---|
| **MASVS-PLATFORM-1** | "The app uses IPC mechanisms securely." This chapter in its entirety: exported components, implicit Intents, redirection, `PendingIntent` mutability. |
| **MASVS-PLATFORM-3** | WebView security — the sink a deep-link URI most often reaches (§5.6). |
| **MASVS-CODE-4** | Input validation. The fix in §5.2 is a validation control; so is deep-link host checking. |
| **MASVS-AUTH-1 / -3** | Authentication and session handling — verified App Links as the anti-hijack control for auth redirects. |
| **MASTG** — deep links and IPC endpoint test procedures | The test *procedures*; §7 of this chapter is the executable version, with the version-dependent commands the MASTG text does not split. |
| **MASWE / MASTG** — "Testing Deep Links", "Testing for Sensitive Functionality Exposure Through IPC" | Where an assessor's checklist will point. |

See [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) for how these identifiers
map onto a report structure.

---

## 4. Vulnerability classes, honestly labelled

This chapter **does not print CVE identifiers it has not verified**, because a
wrong identifier in a report is worse than no identifier. What follows are the
*classes*; each has occurred repeatedly across vendors, and each is findable in the
sources below.

| Where to look | What you will find |
|---|---|
| **Android Security Bulletins** (monthly, `source.android.com/docs/security/bulletin`) | Search the "Framework" and "System" sections for "elevation of privilege" entries whose description mentions intents or `PendingIntent`. Several months every year carry at least one. Each entry links the AOSP commit, which is the best possible worked example of a fix. |
| **Vendor bulletins** (Samsung, Xiaomi, OPPO/OnePlus, Motorola security update pages) | OEM system apps are the richest source of intent-redirection issues, because a pre-installed app's borrowed authority is worth far more than a third-party app's. |
| **Google Play Console — "Intent Redirection vulnerability" warning** | Google's own automated detector, and its help page defines the pattern precisely. Its existence is evidence of how common the SDK-injected version of this bug is. |
| **Chromium bug tracker, `intent:` scheme handling** | The browser-as-deputy case: why browsers strip the component and `FLAG_GRANT_*` when parsing `intent:` URIs, and what happens in browsers that do not. |

---

## 5. Research and talks

Cited by topic rather than by exact title/venue where the author is not certain of
the citation — the *content* is what you want, and it is findable by topic.

| Topic | What it adds |
|---|---|
| **Confused-deputy analyses of Android IPC** (academic literature on permission re-delegation) | The formal framing of what §5.2 describes informally. The "permission re-delegation" line of work is the origin of the vocabulary. |
| **Static analysis of Android ICC** (inter-component communication) — the FlowDroid / IccTA / Epicc family of tools and papers | How the redirection primitive is detected at scale, and why the false-positive rate is what it is. Useful when you are asked why a scanner's output needs triage. |
| **Task-hijacking / StrandHogg research** | Adjacent to this chapter: it abuses `taskAffinity` and `launchMode` rather than resolution. The manifest side is [32-Manifest §3.6](../../32-Manifest/README.md). |
| **Conference talks on deep-link and App-Link abuse** (Black Hat / DEF CON / OBTS mobile tracks, most years) | Real-world chains where an unverified App Link is step one and account takeover is step three. |

---

## 6. Tooling

| Tool | Use in this chapter |
|---|---|
| `adb`, `am`, `cmd package`, `pm`, `dumpsys` | Everything in §7. The device is the primary source. |
| **Frida** | [`../scripts/intent-monitor.js`](../scripts/intent-monitor.js). See [53-Frida](../../53-Frida/README.md) for setup. |
| **Drozer** | `app.activity.info`, `app.activity.start`, `app.broadcast.send`. Its agent is an ordinary app, which makes it a *better* reachability oracle than `adb shell` — the one thing it has over `am`. |
| **Objection** | `android intents launch_activity`, `android hooking watch class android.content.Intent`. |
| **jadx**, **apktool**, **aapt2** | §6 and §8. `aapt2 dump xmltree` is the closest host-side approximation of the platform's own parser. |
| **MobSF** | Bulk manifest triage across many APKs. Not a severity oracle. |
| `apksigner`, `keytool` | The signing-certificate digest for `assetlinks.json` (lab 03). |

---

## 7. This chapter's own artefacts

| File | What it is |
|---|---|
| [`../cheatsheet.md`](../cheatsheet.md) | Every table in one place: fields, actions, categories, matching rules, `am` syntax with all extra types, flags, `PendingIntent`, App Links commands by version. |
| [`../mindmap.md`](../mindmap.md) | The whole chapter as one Mermaid map. |
| [`../faq.md`](../faq.md) | Twenty-one questions, including the ones people are embarrassed to ask. |
| [`../scripts/intent-surface-map.py`](../scripts/intent-surface-map.py) | Runtime Intent-surface mapping from a device; `<data>` cross products; redirection and `PendingIntent` primitives in a decompiled tree. |
| [`../scripts/intent-monitor.js`](../scripts/intent-monitor.js) | Frida: every Intent sent and received, nested `Intent` extras walked recursively, redirection taint tracking, `PendingIntent` mutability at creation time. |
| [`../scripts/appstate-linkcheck.sh`](../scripts/appstate-linkcheck.sh) | App Links verification state, with the command set that exists on the device's platform version. |
| [`../examples/`](../examples/README.md) | The vulnerable router, its fixed counterpart, the identity patterns, and two buildable apps. |
| [`../labs/lab-01-intent-redirection.md`](../labs/lab-01-intent-redirection.md) | The primitive, end to end, with a negative control. |
| [`../labs/lab-02-resolution-forensics.md`](../labs/lab-02-resolution-forensics.md) | Predict, then measure, the resolver. |
| [`../labs/lab-03-applink-verification.md`](../labs/lab-03-applink-verification.md) | Verification state on any Android version. |
| [`../labs/lab-04-ctf-the-courier.md`](../labs/lab-04-ctf-the-courier.md) | Four flags, four mechanisms. |

---

## 8. Related chapters

| Chapter | Relationship to this one |
|---|---|
| [24-IPC](../../24-IPC/README.md) | Where Intents sit among Android's IPC mechanisms. Read first if the word "IPC" is new. |
| Chapter 25 — Binder *(being written)* | **The other half of the identity story.** Binder's kernel driver stamps the caller's UID into the receiving thread, which is why `Binder.getCallingUid()` cannot be forged — and why an Intent, which carries no such stamp, is the source of most of this chapter's bugs. 25 owns the stamping; 26 owns the consequence of its absence. |
| [27-ContentProviders](../../27-ContentProviders/README.md) | **Grant laundering's other half.** This chapter owns the redirection *primitive*; 27 owns what a laundered `content://` grant actually steals, and the provider-side rules that make it possible. §5.4 there is the direct continuation of §5.2 here. |
| [32-Manifest](../../32-Manifest/README.md) | **The declaration audit.** `<intent-filter>` as a static declaration, every attribute, the `targetSdk` export matrix, and `scripts/manifest-audit.py`. Run 32's auditor first, on the APK; this chapter starts where it ends, on the device. |
| [31-Fragments](../../31-Fragments/README.md) | **The reflection sink.** §5.6's row about `Class.forName` on a name from a URI is that chapter's whole subject: a class name in an extra or a query parameter becoming a constructed object. |
| [45-OAuth](../../45-OAuth/README.md) and [its lab 03](../../45-OAuth/labs/lab-03-scheme-hijack.md) | The scheme-hijack attack, staged end to end against an OAuth redirect. This chapter explains the resolution mechanism that permits it (§3.4, §3.11); 45 does the attack and the severity chain. |
| [23-Permissions](../../23-Permissions/README.md) | `protectionLevel`. A `normal`-level custom permission on an exported component is not a control, and this is where you go to be able to say why. |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | The UID boundary that `android:exported` is checked against. Redirection is interesting precisely because it does not break this boundary — it borrows a principal on the far side of it. |
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | Component lifecycles: where `onCreate`, `onNewIntent`, `onReceive` and `onStartCommand` sit, and why `Binder.getCallingUid()` is useless in three of the four. |
| [53-Frida](../../53-Frida/README.md) | Setting up the instrumentation this chapter's monitor needs. |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Why framework method signatures survive R8 and your class names do not — the reason the `check-cast Landroid/content/Intent;` signature in §6.2 works on obfuscated apps. |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Mapping these findings onto MASVS/MASTG identifiers for a report. |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The wider `adb`/`dumpsys` command set. |
| Chapter 29 — BroadcastReceivers | Broadcast delivery policy, ordering, sticky broadcasts and receiver registration. Broadcast *resolution* is here because it is the same algorithm. |
| Chapter 30 — Activities | Tasks, the back stack, `launchMode`, and task hijacking. The task-related `FLAG_ACTIVITY_*` values are listed here for completeness; their stack semantics belong there. |
| Chapter 43 — WebView | The highest-value sink for attacker-controlled deep-link data. |
