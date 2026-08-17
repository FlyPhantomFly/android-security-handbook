# 27 — Content Providers · References

Annotated. Every entry says *why* you would open it, so you can pick the right one at 2 a.m. with a
client waiting.

The chapter's own claims are traceable to these sources. When you need to defend a finding —
"`call()` really does get no permission check" — this is where the proof lives.

---

## Primary source — AOSP

Read these on [cs.android.com](https://cs.android.com/), which gives you cross-references, blame and
per-release history. The navigation technique is in [07-AOSP](../../07-AOSP/README.md).

> **🔍 Pentester's Note**
> Always pin the branch to the release you are testing. `ContentProvider.java` on `main` and on
> `android13-release` differ in ways that matter — `getTypeAnonymous()` does not exist before API 33,
> and the `AttributionSource` parameter threading through `Transport` arrived in Android 12. A
> statement about "the framework" that is true on `main` and false on the device in your hand is a
> statement that will be corrected in the remediation meeting.

### The provider core

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/content/ContentProvider.java` | You need to prove exactly where enforcement happens. The inner `Transport` class is the trust boundary — your subclass is never published over Binder, `Transport` is. **The single most important file in this chapter.** Read `enforceReadPermission`, `enforceWritePermission`, `validateIncomingUri` and, critically, `call()` — to see that it enforces nothing per-URI. |
| `frameworks/base/core/java/android/content/ContentResolver.java` | You are reasoning about the *client* side: `query`, `openInputStream`, `openFileDescriptor`, `call`, `acquireUnstableProvider`. Read `acquireProvider` vs `acquireUnstableProvider` before you write a fuzzer, so you understand why the stable variant kills your own process. |
| `frameworks/base/core/java/android/content/ContentProviderNative.java` | You are looking at a Binder transaction dump and need the transaction codes, or you want to see exactly what gets parcelled for a `query`. `ContentProviderProxy` is the client stub; `ContentProviderNative.onTransact` is the server dispatch. |
| `frameworks/base/core/java/android/content/IContentProvider.java` | You want the interface shape in one screen — the complete external API surface of every provider on the device. |
| `frameworks/base/core/java/android/content/UriMatcher.java` | You need to know precisely what `*` and `#` match, and to confirm that the matcher does **not** normalise `..` in a path. It matches literally against `uri.getPathSegments()`. |
| `frameworks/base/core/java/android/content/ContentProviderClient.java` | You are writing tooling that holds a long-lived handle instead of re-resolving the authority per call. |
| `frameworks/base/core/java/android/net/Uri.java` | You are arguing about what `getLastPathSegment()` can contain after percent-decoding. The answer to "surely a path segment cannot contain a slash" is in this file. |

### Where `system_server` decides

| Path | Open it when |
|---|---|
| `frameworks/base/services/core/java/com/android/server/am/ContentProviderHelper.java` | You need the authoritative answer to "can this UID reach this provider at all?". `getContentProviderImpl()` and `checkContentProviderPermission()` live here on modern releases. This is also where you see that resolving an authority **starts the owning app's process**. On older branches the same logic sits inside `ActivityManagerService.java`. |
| `frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java` | `checkComponentPermission()` — the function containing the two short circuits you must internalise: same-UID callers are allowed unconditionally, and non-exported components are denied to different UIDs regardless of held permissions. |
| `frameworks/base/services/core/java/com/android/server/uri/UriGrantsManagerService.java` | You are investigating a URI-permission grant: how it is created, how it is checked, how `FLAG_GRANT_PREFIX_URI_PERMISSION` widens it, and how persisted grants are serialised. The counterpart to `dumpsys activity permissions`. |
| `frameworks/base/services/core/java/com/android/server/uri/UriPermission.java` | You want the record structure behind a grant — the `(sourceUid, targetUid, GrantUri)` key — so you can reason about exactly what a grant does and does not cover. |
| `frameworks/base/core/java/android/app/ActivityThread.java` | `installContentProviders()` and `acquireProvider()`. Read it to confirm the ordering claim the chapter makes: providers are installed **before** `Application.onCreate()`. This is why a stub provider is the standard library auto-initialiser trick. |
| `frameworks/base/services/core/java/com/android/server/pm/` | `resolveContentProvider` and the parsed `ProviderInfo` — the ground truth for `exported`, `readPermission`, `writePermission`, `pathPermissions` and `grantUriPermissions`, which is what `dumpsys package` prints. Trust this over your decompiler. |

### SQLite and the framework's own defence

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/database/sqlite/SQLiteQueryBuilder.java` | You are writing the remediation. `setStrict()`, `setStrictColumns()`, `setStrictGrammar()` and `setProjectionMap()` are the two-line fix for the entire injection class. Read the implementation so you can tell a developer *why* it works rather than asserting that it does. |
| `frameworks/base/core/java/android/database/sqlite/SQLiteDatabase.java` | You are deciding whether a decompiled call is safe. `rawQuery(sql, args)` binds only `?` placeholders; `query(table, columns, selection, selectionArgs, …)` does the same. Neither protects a concatenated column list or `ORDER BY`. |
| `frameworks/base/core/java/android/database/CursorWindow.java` | You want to understand why a `Cursor` crossing a process boundary is shared memory rather than a Binder payload, and why a leaked `Cursor` leaks a file descriptor in **both** processes. |

### Files, FDs and `FileProvider`

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/os/ParcelFileDescriptor.java` | You need `parseMode()`'s exact mapping from `"r"`/`"w"`/`"rwt"` to open flags, and the FD-passing mechanics that make an `openFile` traversal a genuine sandbox bypass rather than a mediated data leak. |
| AndroidX `androidx/core/content/FileProvider.java` (source in the AndroidX repository; also readable in any app's decompiled output) | You are deciding whether a `FileProvider` finding is in the library or in the configuration. `getUriForFile()` and `openFile()` both canonicalise and check containment, so the bug is almost always the `<paths>` resource, a hand-rolled clone, or an app code path that lets an attacker choose the `File`. |
| `frameworks/base/core/java/android/provider/DocumentsProvider.java` | Your target uses the Storage Access Framework. `DocumentsProvider` is a `ContentProvider` subclass with its own `queryChildDocuments`/`openDocument` surface and its own traversal opportunities. |

### The `content` command itself

| Path | Open it when |
|---|---|
| `frameworks/base/cmds/content/src/com/android/commands/content/Content.java` | You want to know exactly what `content query --projection` does with your string, which flags exist on the release you are testing, and which operations the CLI simply cannot express. Reading this file once saves you from concluding "the provider rejected it" when the truth is "the CLI never sent it". |

> **🔬 Under the Hood**
> `content` is a Java program launched by a shell wrapper (`/system/bin/content`) that runs under the
> `shell` UID with `app_process`. It builds a real `ContentResolver` against the shell's own identity.
> That is precisely why it is *not* an attacker simulation — the identity it uses is UID 2000, which
> holds privileges no third-party app has. The source is where you confirm that, rather than taking
> the chapter's word for it.

---

## Official documentation

| Resource | Why you would open it |
|---|---|
| [Content providers overview](https://developer.android.com/guide/topics/providers/content-providers) | The conceptual map. Send this to a developer, not to yourself. |
| [Creating a content provider](https://developer.android.com/guide/topics/providers/content-provider-creating) | Read it to see *what Google tells developers to do* — then compare against what you find in the client's code. The gap is your finding list. |
| [Content provider basics](https://developer.android.com/guide/topics/providers/content-provider-basics) | The client-side contract, including the `Bundle`-based query arguments introduced at API 26. |
| [`<provider>` manifest element](https://developer.android.com/guide/topics/manifest/provider-element) | The definitive attribute reference. Cite it when you need to state a default in a report. |
| [`<grant-uri-permission>` element](https://developer.android.com/guide/topics/manifest/grant-uri-permission-element) | Confirms the counter-intuitive rule: `grantUriPermissions="true"` with **no** children is the *broadest* configuration, not the narrowest. |
| [`<path-permission>` element](https://developer.android.com/guide/topics/manifest/path-permission-element) | The element chapter [32-Manifest](../../32-Manifest/README.md) audits in depth. Read it before claiming a path is protected — a `<path-permission>` can **widen** access, and unmatched paths fall back to the provider-level permission rather than being denied. |
| [`FileProvider`](https://developer.android.com/reference/androidx/core/content/FileProvider) | The `<paths>` element reference, and the statement that `getUriForFile` canonicalises. |
| [Sharing files](https://developer.android.com/training/secure-file-sharing) | The intended `FileProvider` workflow — grant, don't export. Useful as the "correct pattern" citation in a remediation section. |
| [App security best practices — IPC](https://developer.android.com/topic/security/best-practices) | Google's own wording for "do not export unless you must". Quoting the vendor's guidance back at a developer is more persuasive than quoting a pentester. |
| [Package visibility filtering](https://developer.android.com/training/package-visibility) | Android 11 changed what your test harness can enumerate. Read this before concluding a device is clean. |
| [Storage Access Framework / document provider](https://developer.android.com/guide/topics/providers/document-provider) | When the target exposes a `DocumentsProvider`. |
| [Behaviour changes by API level](https://developer.android.com/about/versions) | Check here before asserting *any* version-dependent claim. Provider behaviour changed at 17, 24, 26, 29, 30, 31 and 33. |

---

## Tooling

| Tool | Where | Use it for |
|---|---|---|
| `content` | `/system/bin/content` on any device | The fastest possible probe: `query`, `insert`, `update`, `delete`, `call`, `read`, `write`, `gettype`. Remember it runs as UID 2000. |
| `dumpsys package providers` | on device | Every provider on the device with authority, package and export state. The whole-device sweep starts here. |
| `dumpsys activity providers` | on device | Which providers are currently *instantiated* and who holds references to them. |
| `dumpsys activity permissions` | on device | Live URI-permission grants. The runtime view of [§3.6](../README.md#36-uri-permissions-the-temporary-grant-system). |
| [Drozer](https://github.com/WithSecureLabs/drozer) | host + agent APK | **The reachability tool.** Its agent is an ordinary unprivileged app, so a Drozer result is evidence in a way an `adb shell` result is not. `app.provider.info`, `app.provider.finduri`, `app.provider.query`, `app.provider.read`, `scanner.provider.injection`, `scanner.provider.traversal`. Note the gaps: no `call()` module, and the injection scanner does not test `sortOrder`. |
| [Frida](https://frida.re/docs/android/) | host + device | Server-side observation: hook `ContentProvider.query`/`openFile`/`call` and `SQLiteDatabase.rawQuery` to see what the provider *did* with your input. See [`../scripts/hook-provider.js`](../scripts/hook-provider.js) and [53-Frida](../../53-Frida/README.md). |
| [Frida Java API](https://frida.re/docs/javascript-api/#java) | docs | `Java.use`, overload resolution, `Java.cast`. You will need overload disambiguation constantly, because `query` has four overloads and `call` has two. |
| [Objection](https://github.com/sensepost/objection) | host | `android hooking watch class_method … --dump-args --dump-backtrace`. The backtrace is what tells you whether a `query` came from the app's own UI or from a Binder thread serving an external caller. See [54-Objection](../../54-Objection/README.md). |
| [jadx](https://github.com/skylot/jadx) | host | Reading the provider's `query`, `openFile` and `call` implementations. Obfuscation cannot hide them — the signatures override framework methods. See [56-JADX](../../56-JADX/README.md). |
| [apktool](https://apktool.org/) | host | Decoding the merged manifest and `res/xml/*.xml`, which is where the `FileProvider` `<paths>` file lives under a name you cannot guess. |
| `aapt2 dump xmltree` | Android SDK build-tools | The independent second opinion on the binary manifest. `(type 0x12)0xffffffff` is `true`, `(type 0x12)0x0` is `false`. Disagreement with `apktool` is itself a finding. |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | host | Fast first pass over a corpus. Blind to `sortOrder` injection, `call()` methods, traversal requiring canonicalisation analysis, and deputy chains. See [55-MobSF](../../55-MobSF/README.md). |
| `sqlite3` | host | Opening a database you pulled through a traversal — with its `-wal` and `-shm` files present so SQLite replays them. |
| [`../scripts/provider-enum.sh`](../scripts/provider-enum.sh) | this chapter | Whole-device or per-package provider enumeration with read attempts and an explicit shell-vs-app reachability caveat on every line. |
| [`../scripts/provider-call-fuzz.py`](../scripts/provider-call-fuzz.py) | this chapter | The `call()` fuzzer Drozer does not have, plus all four injection points including `sortOrder` and the URI path. |
| [`../scripts/hook-provider.js`](../scripts/hook-provider.js) | this chapter | Server-side observation of every provider entry point. |

---

## OWASP

| Resource | Relevance |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | The control framework clients ask you to map to. |
| **MASVS-PLATFORM-1** — "the app uses IPC mechanisms securely" | The primary mapping for this entire chapter: exported providers, permissions, `call()`, URI grants. |
| **MASVS-PLATFORM-2** — WebView configuration | Indirect but real: `WebSettings.setAllowContentAccess(true)` lets JavaScript in a WebView reach `content://` URIs. See [43-WebView](../../43-WebView/README.md). |
| **MASVS-STORAGE-1 / -2** — secure storage, no unintended exposure | An `openFile` traversal into `shared_prefs` is a STORAGE finding as much as a PLATFORM one. Map it to both; clients track them separately. See [33-Storage](../../33-Storage/README.md). |
| **MASVS-CODE-4** — input validation | SQL injection and path traversal. |
| [MASTG](https://mas.owasp.org/MASTG/) | The test procedures. The Android platform-APIs chapter contains the exported-provider, injection and traversal test cases that mirror [§5.1–5.3](../README.md#5-security-perspective). |
| MASTG test apps and the UnCrackable series | Practice targets. See [80-Appendix](../../80-Appendix/README.md). |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | This repository's full treatment of the mapping. |

> **⚠️ Warning — on citing vulnerability identifiers**
> This chapter deliberately describes vulnerability **classes** rather than naming CVE IDs or linking
> bug bounty reports. Provider bugs are numerous, version-specific and frequently reported under
> vendor-internal identifiers, and a misattributed CVE in a client report costs you more credibility
> than omitting the citation entirely. When you need a specific reference, pull it from the
> [Android Security Bulletin](https://source.android.com/docs/security/bulletin) for the affected
> release, and quote the bulletin's own wording.

---

## Security research and disclosure sources

| Resource | Why |
|---|---|
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Monthly, authoritative. Read for the *pattern* of which components recur, not to memorise identifiers. Provider and URI-grant issues appear regularly under the Framework component. |
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | The highest-quality public writing on Android IPC and confused-deputy chains. |
| [Android VRP rules](https://bughunters.google.com/about/rules/android-friends) | What Google itself considers a reportable provider vulnerability and at what severity. Useful for calibrating your own severity ratings against an external standard. |
| [Android Code Search](https://cs.android.com/) | Not a paper, but the single most useful research tool in this list. |

---

## Books and long-form

| Work | Why |
|---|---|
| *Android Security Internals* — Nikolay Elenkov | The best structural account of the permission model that providers sit inside. Dated in specifics, still correct in shape. |
| *The Android Hacker's Handbook* — Drake et al. | Historical, but the IPC attack methodology chapters remain a good model for how to reason about component reachability. |
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | For the Binder and `system_server` layers underneath everything here. |
| *The Tangled Web* / general confused-deputy literature | If you want the theory behind [§5.4](../README.md#54-uri-permission-laundering-via-intent-redirection) rather than the recipe. The confused-deputy problem was described by Norm Hardy in 1988; the paper is short and worth reading once. |

---

## Conference talks worth finding

Search by topic rather than URL, since hosting moves:

- Android IPC attack surface and exported components — Black Hat / DEF CON mobile tracks
- Intent redirection and URI-permission laundering — Google's own Android security team talks
- Drozer methodology — the original WithSecure/MWR material, still the clearest exposition
- Content provider SQL injection at scale — academic corpus-analysis papers (USENIX Security, NDSS)

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | The UID isolation that makes providers necessary in the first place. Read before this chapter. |
| [23-Permissions](../../23-Permissions/README.md) | Protection levels, custom permissions and permission squatting — you cannot triage a provider without this. |
| [24-IPC](../../24-IPC/README.md) | Where providers sit among the IPC mechanisms. |
| [25-Binder](../../25-Binder/README.md) | The transport underneath every provider call, and the source of `Binder.getCallingUid()` — the only caller identity you can trust. |
| [26-Intent](../../26-Intent/README.md) | Intent redirection: the other half of grant laundering. Chapter 26 owns the redirection primitive; chapter 27 owns what it steals. |
| [28-Services](../../28-Services/README.md) | The typed AIDL alternative to `call()`, and the correct recommendation when a client insists they need RPC. |
| [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) | The other unauthenticated entry point on the component surface. |
| [30-Activities](../../30-Activities/README.md) | The deputy components that launder grants. |
| [32-Manifest](../../32-Manifest/README.md) | **The declaration-side audit.** Chapter 32 owns permission precedence, `<path-permission>`, `<grant-uri-permission>` and the `<paths>` resource as *manifest* objects; this chapter owns runtime exploitation. [`32-Manifest/labs/lab-04-provider-surgery.md`](../../32-Manifest/labs/lab-04-provider-surgery.md) is the companion to this chapter's labs — do it first if you have not. |
| [33-Storage](../../33-Storage/README.md) | What a traversal actually reaches: `shared_prefs`, `databases`, WAL files, scoped storage. |
| [43-WebView](../../43-WebView/README.md) | `setAllowContentAccess` — reaching providers from JavaScript inside the target app. |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | The wider runtime methodology this chapter's Frida work sits inside. |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | The wider static methodology behind [§8](../README.md#8-static-analysis). |
| [53-Frida](../../53-Frida/README.md) | The hooking mechanics behind [`../scripts/hook-provider.js`](../scripts/hook-provider.js). |
| [54-Objection](../../54-Objection/README.md) | The batteries-included wrapper for the same hooks. |
| [55-MobSF](../../55-MobSF/README.md) | The scanner, and its blind spots. |
| [56-JADX](../../56-JADX/README.md) | Reading provider implementations in decompiled form. |
| [60-ADB](../../60-ADB/README.md) | Why `adb shell` is UID 2000, in detail. The mechanical basis of this chapter's central discipline. |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | MASVS/MASTG in full. |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The `content` and `dumpsys` command reference, and [`lab-03-exported-sweep.md`](../../77-UsefulCommands/labs/lab-03-exported-sweep.md), which is the general form of the reachability discipline applied to all four component types. |
| [80-Appendix](../../80-Appendix/README.md) | Deliberately vulnerable practice targets. |
