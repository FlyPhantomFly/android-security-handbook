# 24 — IPC · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure rather than reading a link list.

---

## Primary source — AOSP

Read these on [cs.android.com](https://cs.android.com/), which gives you cross-references, blame and
history. See [07-AOSP](../../07-AOSP/README.md) for the navigation technique — in particular, search
for a *string you saw in an exception message*, because that is almost always the fastest route to
the enforcing function.

### The files that decide whether an app can reach a component

| Path | Open it when |
|---|---|
| `frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java` | You want `checkComponentPermission`. **The single most important function in this chapter** — four rules that answer every "can this app reach that component?" question, including the same-UID rule the confused deputy abuses. |
| `frameworks/base/services/core/java/com/android/server/wm/ActivityStarter.java` | You need to know exactly where `Permission Denial: starting Intent` is produced, and what else can reject a start before permissions are even considered. |
| `frameworks/base/services/core/java/com/android/server/uri/UriGrantsManagerService.java` | You are proving URI-grant theft and need to see **who is recorded as the granter** when `FLAG_GRANT_READ_URI_PERMISSION` is honoured. This file is the reason the deputy attack works. |
| `frameworks/base/services/core/java/com/android/server/am/ContentProviderHelper.java` | A provider acquisition failed and you want to know which of the several checks refused you. |
| `frameworks/base/services/core/java/com/android/server/am/BroadcastQueue.java` | You are reasoning about ordered delivery, priority, `abortBroadcast`, or receiver-permission enforcement. |

### Binder — the substrate

| Path | Open it when |
|---|---|
| `drivers/android/binder.c` (Linux kernel) | You want to see, in `binder_transaction()`, that the sender's UID is copied from the calling task's credentials and not from the parcel. This is the source of the "cannot be forged" guarantee. |
| `frameworks/native/libs/binder/IPCThreadState.cpp` | The BC_/BR_ command loop, and where `mCallingUid` / `mCallingPid` are stored in thread-local state for the duration of a transaction. |
| `frameworks/native/libs/binder/Parcel.cpp` | You are hand-crafting a transaction, or investigating a Parcel/Bundle mismatch. |
| `frameworks/base/core/java/android/os/Binder.java` | `clearCallingIdentity`, `restoreCallingIdentity`, `execTransact`, and the `getCallingUidOrThrow` variant that refuses to silently return your own UID. |
| `frameworks/base/core/jni/android_util_Binder.cpp` | How `Binder.getCallingUid()` in Java reaches the native thread state. |
| `frameworks/native/cmds/servicemanager/` | Name registration and the SELinux hook that decides who may `addService` — which is why an ordinary app cannot publish a named system service. |

### The mechanisms

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/net/LocalSocketAddress.java` | You want to see, in ten lines, that the single-argument constructor defaults to `Namespace.ABSTRACT`. This is §3.10's entire premise, straight from the source. |
| `frameworks/base/core/jni/android_net_LocalSocketImpl.cpp` | The JNI layer that writes the NUL into `sun_path[0]` and computes the address length. There is no permission check anywhere in the path, because the kernel has nothing to check against. |
| `frameworks/base/core/java/android/content/Intent.java` | The complete field list, `parseUri`, `fillIn`, and `migrateExtraStreamToClipData` — the last of which surprises people. |
| `frameworks/base/core/java/android/content/IntentFilter.java` | The exact matching algorithm for action, categories and data. Read it before arguing about whether a filter matches. |
| `frameworks/base/core/java/android/content/ContentProvider.java` | `Transport.query` and `enforceReadPermissionInner` — the **second** permission check, performed inside the provider's own process on every call. |
| `frameworks/base/core/java/android/app/PendingIntent.java` and `services/core/java/com/android/server/am/PendingIntentRecord.java` | Why a `PendingIntent` executes with its *creator's* identity, and what mutability actually changes. |
| `frameworks/base/core/java/android/os/MemoryFile.java`, `SharedMemory.java` | Shared-memory creation and the `memfd` sealing path. |
| `system/core/libcutils/ashmem-dev.cpp` | ashmem creation and the memfd fallback, when you need the native truth. |
| `frameworks/base/services/core/java/com/android/server/clipboard/ClipboardService.java` | The focus-based read restriction introduced in Android 10, and exactly what it does and does not stop. |
| `frameworks/base/packages/SettingsProvider/` | Confirms that `Settings.*` is an ordinary `ContentProvider`, which is why `content query` reaches it. |

---

## Official documentation

| Resource | Why |
|---|---|
| [Intents and intent filters](https://developer.android.com/guide/components/intents-filters) | The canonical description of resolution. Read the "Intent resolution" section before disputing a match. |
| [Bound services and AIDL](https://developer.android.com/guide/components/aidl) | The developer-facing framing you are auditing against. Notice how little it says about caller verification — that absence is why §5.2.1 exists. |
| [`Messenger`](https://developer.android.com/reference/android/os/Messenger) | Check the `sendingUid` documentation. Almost nobody uses it, which is the finding. |
| [Content provider basics](https://developer.android.com/guide/topics/providers/content-provider-basics) | Authorities, URIs and the permission attributes, in the vendor's own words. |
| [`FileProvider`](https://developer.android.com/reference/androidx/core/content/FileProvider) | The correct answer whenever you are about to recommend "share the file". |
| [Permissions overview](https://developer.android.com/guide/topics/permissions/overview) | The protection-level table you cite when explaining why `normal` is not a control. |
| [App links verification](https://developer.android.com/training/app-links/verify-android-applinks) | Everything about `assetlinks.json`, including the failure modes that silently degrade an App Link to a hijackable custom link. |
| [`android.net.LocalSocket`](https://developer.android.com/reference/android/net/LocalSocket) | Worth reading precisely because of what it *does not* warn you about. |
| [Package visibility filtering](https://developer.android.com/training/package-visibility) | Read before writing any probe app, or your `<queries>` block will be wrong and every result a false negative. |
| [Behaviour changes by API level](https://developer.android.com/about/versions) | Check before asserting any version-dependent claim. Half the mitigations in this chapter are `targetSdk`-gated. |
| [Android security tips](https://developer.android.com/privacy-and-security/security-tips) | The IPC section is short, correct, and useful to quote back to a developer. |
| [App sandbox](https://source.android.com/docs/security/app-sandbox) | The boundary that IPC exists to cross. |

---

## Tooling

| Tool | Where | Use |
|---|---|---|
| `adb` | host | `dumpsys package`, `am`, `content`, `service list`, and reading `/proc`. The whole live methodology is these. See [60-ADB](../../60-ADB/README.md). |
| [Drozer](https://github.com/WithSecureLabs/drozer) | host + device agent | The right tool for **reachability proof**, because its agent runs as an ordinary app. `scanner.provider.injection` and `scanner.provider.traversal` are the two highest-value commands in the whole tool. See [54-Objection](../../54-Objection/README.md) for the alternative workflow. |
| [Frida](https://frida.re/docs/android/) | host + device | Everything in §7.3. Start with [`../scripts/trace-ipc.js`](../scripts/trace-ipc.js). See [53-Frida](../../53-Frida/README.md). |
| [Objection](https://github.com/sensepost/objection) | host | `android hooking list activities/services/receivers` and `android intent launch_activity` when you want results in seconds without writing a script. |
| [jadx](https://github.com/skylot/jadx) | host | The decompiler you grep. AIDL `Stub` classes survive obfuscation legibly — §6.1. |
| [apktool](https://apktool.org/) | host | The manifest, properly. Always cross-check with `aapt2 dump xmltree`, because a crafted APK can make the two disagree — see [10-APK-Internals](../../10-APK-Internals/README.md). |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | host | Fine for a first-pass component inventory. Understand that it reads the manifest, so it is structurally blind to abstract sockets, localhost listeners, shared memory and file modes. See [55-MobSF](../../55-MobSF/README.md). |
| `strace` | device, root | `-e trace=socket,bind,connect,accept` catches a socket being created at the moment it happens, including from native code no Java hook would see. |
| This chapter's scripts | [`../scripts/`](../scripts/) | `enumerate-ipc-surface.sh`, `abstract-socket-probe.py`, `ipc-surface-report.py`, `trace-ipc.js`, `hook-binder-identity.js`. |
| This chapter's probe APK | [`../examples/attacker-app/`](../examples/attacker-app/README.md) | The only artefact that proves app-level reachability rather than shell-level reachability. |

---

## OWASP

| Resource | Relevance |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | **MASVS-PLATFORM-1** — "the app uses IPC mechanisms securely" — is the control this entire chapter maps to. **MASVS-PLATFORM-2** covers WebViews, which is where deep-link findings usually terminate. **MASVS-PLATFORM-3** covers UI-level abuse reached through IPC: task hijacking, tapjacking, overlays. |
| [MASTG](https://mas.owasp.org/MASTG/) | The "Android Platform APIs" test group is the closest published procedure to §3.22. Use it as a coverage checklist in a report — *not* as a substitute for the manual reach-through analysis, which no checklist can encode. |
| MASVS-STORAGE-1 / -2 | World-readable files, shared storage, clipboard and logs — the storage-shaped half of the IPC surface. See [33-Storage](../../33-Storage/README.md). |
| MASVS-CODE-4 | "Validates and sanitises all untrusted inputs" — Intent extras, provider parameters and socket protocols are all untrusted inputs. |
| [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | M8 Security Misconfiguration and M4 Insufficient Input/Output Validation are the two buckets IPC findings land in when a client asks for Top-10 mapping. |
| MASTG test apps (UnCrackable and the MASTG app series) | Practice targets with deliberately exposed components. See [80-Appendix](../../80-Appendix/README.md). |

---

## Research and background

| Work | Why |
|---|---|
| Norm Hardy, *The Confused Deputy (or why capabilities might have been invented)*, ACM SIGOPS OSR, 1988 | Four pages. The original statement of the problem, and still the clearest. Read it once and §3.20 stops needing memorisation. |
| Chin, Felt, Greenwood, Wagner, *Analyzing Inter-Application Communication in Android*, MobiSys 2011 | The paper that named the Android intent-attack classes you use every day — broadcast injection, activity/service hijacking, intent spoofing. |
| Felt, Wang, Moshchuk, Hanna, Chin, *Permission Re-Delegation: Attacks and Defenses*, USENIX Security 2011 | The confused deputy specialised to Android permissions, with measurements. Useful when a client asks "how common is this really?". |
| Lu, Li, Wu, Lee, Jiang, *CHEX: Statically Vetting Android Apps for Component Hijacking Vulnerabilities*, CCS 2012 | The origin of most component-hijacking static analysis. Read it to understand why your scanner produces the false positives it does. |
| Arzt et al., *FlowDroid*, PLDI 2014 | Taint analysis for Android, and the basis of most automated IPC-flow tooling. The source/sink framing is the vocabulary to use when designing detection at scale. |
| `man 7 unix` | The authoritative description of the **abstract namespace** and `SO_PEERCRED`. Two paragraphs that settle every argument about §3.10. |
| `man 2 memfd_create`, `man 2 fcntl` (F_ADD_SEALS) | memfd and file sealing, for the shared-memory fix in §3.13. |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Monthly, authoritative. Read for the *pattern* of which subsystems recur rather than for individual entries. |
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | The highest-quality public work on Android IPC and Binder bugs. |
| [Android VRP rules](https://bughunters.google.com/about/rules/android-friends) | What Google itself considers reportable, and its severity model — a useful external anchor when a client disputes a rating. |

> **Note on CVE citation.** This chapter deliberately describes vulnerability *classes* rather than
> naming identifiers. Android IPC bugs are numerous, version-specific and frequently
> vendor-specific, and a misattributed CVE in a client report is worse than no citation at all. When
> you need a specific reference, pull it from the bulletin for the affected release, verify the
> affected versions yourself, and cite it with the release it applies to. Never cite one from memory
> or from a blog post.

---

## Books and long-form

| Work | Why |
|---|---|
| *Android Security Internals* — Nikolay Elenkov | The best structural account of the permission and IPC model, including Binder-level identity. Dated in specifics, still the right mental model. |
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | The deepest published treatment of the low-level plumbing, including `servicemanager` and the binder driver. Occasionally idiosyncratic, unmatched on detail. |
| *The Mobile Application Hacker's Handbook* — Chell, Erasmus, Colley, Whitehouse | Dated on tooling, but the IPC methodology chapters are still a good model for how to *structure* an assessment. |
| *The Android Hacker's Handbook* — Drake et al. | Historical, and useful precisely for that: it shows what the surface looked like before the mitigations, which is what a low-`targetSdk` app still gets. |
| *Secure Coding in C and C++* — Seacord | Not Android, but the shared-memory TOCTOU material in §3.13 is a general systems problem, and this is where to learn it properly. |

---

## Conference talks worth finding

Search by topic rather than URL, since hosting moves:

- Android intent redirection and URI-grant theft — Black Hat and DEF CON mobile tracks; several
  vendors have published full-chain writeups.
- Package visibility and `<queries>` in practice — Android Dev Summit sessions cover the developer
  side; the security implications are mostly in blog form.
- Binder internals and fuzzing — OffensiveCon and Recon.
- Deep links, App Links and OAuth on mobile — OWASP AppSec and the IETF OAuth working group's mobile
  best-practice discussions.

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | The platform model IPC sits inside — read first if the trust boundaries in §2.4 feel abstract. |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | The boundary every IPC channel crosses, and why UID separation is the strong part. |
| [22-SELinux](../../22-SELinux/README.md) | The mandatory access control that decides whether `untrusted_app` may reach a socket that DAC does not protect. This is the chapter that explains why a shell result and an app result can differ. |
| [23-Permissions](../../23-Permissions/README.md) | Protection levels in full, and why only `signature` counts. |
| [25-Binder](../../25-Binder/README.md) | The transport, in depth: parcels, transaction codes, the driver. |
| [26-Intent](../../26-Intent/README.md) | The message format, resolution, deep links and redirection in full. |
| [27-ContentProviders](../../27-ContentProviders/README.md) | Providers, URI grants, SQL injection and `openFile` traversal. |
| [28-Services](../../28-Services/README.md) | Bound service lifecycle, AIDL and `Messenger`. |
| [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) | Broadcasts in both directions, ordered delivery and protected broadcasts. |
| [30-Activities](../../30-Activities/README.md) | Task affinity, launch modes and task hijacking. |
| [31-Fragments](../../31-Fragments/README.md) | What an attacker-controlled `Bundle` is worth after it arrives: a Fragment's `getArguments()`, and the reflective loader that chose the Fragment. |
| [32-Manifest](../../32-Manifest/README.md) | Reading a manifest properly, including for what is *absent*. |
| [33-Storage](../../33-Storage/README.md) | Shared files, scoped storage and `FileProvider`. |
| [43-WebView](../../43-WebView/README.md) | Where deep-link and redirection findings usually terminate, and the home of `@chrome_devtools_remote`. |
| [45-OAuth](../../45-OAuth/README.md) | Why custom-scheme redirects are hijackable and what PKCE and App Links change. |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | The runtime methodology §7 is an instance of. |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | The static methodology §8 is an instance of. |
| [53-Frida](../../53-Frida/README.md) | The instrumentation used throughout §7. |
| [60-ADB](../../60-ADB/README.md) | Every command in §7.1, and the `shell` UID whose privileges you must keep separate from an app's. |
| [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) | Where trust-boundary 3 — platform and kernel — is attacked, as opposed to the app-level boundary 2 this chapter covers. |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | The MASVS/MASTG mapping in report form. |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The command reference, and [lab 03](../../77-UsefulCommands/labs/lab-03-exported-sweep.md), which is the reachability discipline drilled end to end. |
