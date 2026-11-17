# 30 — Activities: References

Annotated. Nothing is listed here that was not actually useful in writing the chapter, and where a
source is commonly misread the annotation says so.

---

## AOSP source

Paths are stable enough to navigate by. **No line numbers appear anywhere in this repository** — this
part of the tree was reorganised in Android 10 (`ActivityTaskManagerService` split out of
`ActivityManagerService`) and again in Android 12 (`ActivityStack` folded into `Task`,
`ActivityDisplay` became `TaskDisplayArea`), so expect to `grep` rather than to jump.

| Path | Annotation |
|---|---|
| `frameworks/base/services/core/java/com/android/server/wm/ActivityStarter.java` | The decision engine, and the file this chapter is really about. `executeRequest` does resolution and `checkStartAnyActivityPermission`; `computeLaunchingTaskFlags` adds the implied `FLAG_ACTIVITY_NEW_TASK`; `getReusableTask` performs the affinity lookup the classic hijack must fool; `recycleTask` implements `singleTask`'s destroy-everything-above behaviour. |
| `frameworks/base/services/core/java/com/android/server/wm/ActivityRecord.java` | Where the **effective** task affinity is derived from the parsed manifest value with the declaring app's uid prefixed. This is the transformation measured in README §3.7, and reading this file is the fastest way to convince yourself the manifest and the runtime genuinely disagree. |
| `frameworks/base/services/core/java/com/android/server/wm/Task.java` | The task object: the ordered list of records, `affinity`, `rootAffinity`, the base Intent, the real activity. |
| `frameworks/base/services/core/java/com/android/server/wm/ActivityTaskManagerService.java` | The Binder endpoint every `startActivity` arrives at. |
| `frameworks/base/services/core/java/com/android/server/wm/RootWindowContainer.java` | The container hierarchy: displays, and beneath them tasks. |
| `frameworks/base/services/core/java/com/android/server/wm/TaskDisplayArea.java` | Where tasks are searched for reuse on one display. |
| `frameworks/base/core/java/android/app/Activity.java` | The public API. Worth reading `startActivityForResult` specifically: `startActivity` passes `requestCode == -1`, and that default is the entire reason `getCallingActivity()` returns `null` most of the time. |
| `frameworks/base/core/java/android/app/Instrumentation.java` | `execStartActivity` — the funnel every start in the process passes through, and therefore the correct single hook point. `checkStartActivityResult` is what turns the system's integer error into the `SecurityException` you see. |
| `frameworks/base/core/java/android/app/ActivityThread.java` | The app-side receiver of launch transactions; `handleLaunchActivity` drives `onCreate`. |
| `frameworks/base/core/java/android/app/servertransaction/LaunchActivityItem.java` | The transaction object that makes an Activity exist. |
| `frameworks/base/core/java/android/content/pm/ActivityInfo.java` | `LAUNCH_SINGLE_TASK` and friends, and `taskAffinity` **as declared** — the bare string, before the uid prefix. |
| `frameworks/base/core/java/android/view/View.java` | `onFilterTouchEventForSecurity`. Five lines, and they are the whole tapjacking defence. Read them to see that the condition is an `AND` and that the flag is per-view. |
| `frameworks/base/core/java/android/view/MotionEvent.java` | `FLAG_WINDOW_IS_OBSCURED` (`0x1`) and `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` (`0x2`, API 29+). |
| `frameworks/base/services/core/java/com/android/server/wm/WindowManagerService.java` | Window z-order and input dispatch — where the obscured flag is decided. Different subsystem from everything else in this chapter, which is why tapjacking has different mitigations. |
| `frameworks/base/services/core/java/com/android/server/uri/UriGrantsManagerService.java` | Where a laundered URI grant is actually issued. The permission question is asked about the **caller** and the answer is recorded for the **target**; a deputy separates the two. |

---

## Official Android documentation

| Link | Annotation |
|---|---|
| [Tasks and the back stack](https://developer.android.com/guide/components/activities/tasks-and-back-stack) | The canonical description of `launchMode`, `taskAffinity`, `allowTaskReparenting` and the flags. **Read it, then measure it.** Several statements are easy to misread — in particular, readers routinely come away believing `singleTask` always creates a new task, which README §3.4 disproves on a device. |
| [The activity lifecycle](https://developer.android.com/guide/components/activities/activity-lifecycle) | The callback order used throughout README §3.1. Does not emphasise the `onNewIntent` / `getIntent()` staleness trap, which is where the security bugs are. |
| [`<activity>` manifest element](https://developer.android.com/guide/topics/manifest/activity-element) | Every attribute with its API level. The security audit of these attributes belongs to [32-Manifest §3.6](../../32-Manifest/README.md). |
| [`<activity-alias>` manifest element](https://developer.android.com/guide/topics/manifest/activity-alias-element) | The entry point people forget. Its `exported` and `permission` are its **own** and do not inherit from the target Activity. |
| [App security best practices](https://developer.android.com/privacy-and-security/security-best-practices) | Contains the official statement on tapjacking and `filterTouchesWhenObscured`. Short; the reasoning for *discard rather than warn* is in README §3.9. |
| [Package visibility filtering](https://developer.android.com/training/package-visibility) | The `<queries>` element. Directly responsible for the null-cursor trap in README §7.5 — worth reading before you write any attacker app targeting API 30+. |
| [`WindowManager.LayoutParams`](https://developer.android.com/reference/android/view/WindowManager.LayoutParams) | `TYPE_APPLICATION_OVERLAY`, `FLAG_NOT_TOUCHABLE`, `FLAG_NOT_FOCUSABLE`, `FLAG_SECURE`. The overlay attack is entirely constructed from constants on this one class. |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | **The authoritative record for any CVE claim in this area.** Verify an identifier and its affected-version range here before putting it in a report; a vendor blog post is not a substitute. |
| [`dumpsys` documentation](https://developer.android.com/tools/dumpsys) | Background on the tool. It does not document the `activity activities` output format, which is why README §3.2 annotates a real capture field by field. |

---

## Research and disclosures

| Work | Annotation |
|---|---|
| "Towards Discovering and Understanding Task Hijacking in Android" — Ren, Zhang, Wang, Chen, Mao. **USENIX Security 2015** | The systematic study that named and classified the family, including both the `taskAffinity` and `allowTaskReparenting` variants and several others. Read this before writing about the class; most later blog posts are partial retellings of it. |
| **"StrandHogg"** — Promon vendor research, 2019 | Disclosure of in-the-wild exploitation of the affinity variant against banking apps. Treat the name as a label for a class rather than for one bug — it is used loosely everywhere. |
| **"StrandHogg 2.0"** — Promon, 2020, tracked as **CVE-2020-0096** | A **code-based** variant requiring no manifest declaration, and therefore invisible to every manifest scanner. **Verify the identifier and the affected-version range in the Android Security Bulletin for May 2020 before citing it.** Its lasting lesson is methodological: a checklist that greps for `taskAffinity` has already missed one published family. |

---

## Tools

| Tool | Annotation |
|---|---|
| `dumpsys activity activities` | The primary source for everything in this chapter.it prints the whole graph **twice** — once per display, once in a summary — so key by task id. |
| `dumpsys activity recents` | Tasks that outlived their processes, with `affinity`, `realActivity` and `baseIntent`. The state a parked hijack task sits in. |
| `dumpsys window windows` | Window z-order and `mOwnerUid` — the only way to answer "whose overlay was that". |
| `cmd appops query-op SYSTEM_ALERT_WINDOW allow` | Who holds the overlay permission. On an OEM device this legitimately returns twenty-odd system packages; seeing that once stops you reporting it as a finding. |
| `am start` | Indispensable and limited in three specific ways — always implies `FLAG_ACTIVITY_NEW_TASK`, has no `--eparcelable`, and runs as the privileged uid 2000. README §7.3. |
| [Frida](https://frida.re/) | Used for `scripts/activity-trace.js`. Version 16.1.6 was used for the measurements in this chapter. Setup is [53-Frida](../../53-Frida/README.md). |
| Drozer | `run app.activity.info` / `run app.activity.start`. Its agent runs as a real app rather than as shell, which is a genuine advantage over `am` for reachability — but it knows nothing about tasks. |
| `aapt2 dump xmltree` / `apktool` | The static side. `aapt2` needs no decode step and is the faster of the two for a manifest question. |

---

## This chapter's artefacts

| File | Annotation |
|---|---|
| [`../scripts/task-affinity-map.py`](../scripts/task-affinity-map.py) | Parses the live task graph, decides the affinity-namespacing verdict **empirically**, and flags squatted affinities, mixed-package tasks and task-owning launch modes. Severity is conditioned on the verdict, so a mitigated configuration is reported as INFO rather than HIGH. |
| [`../scripts/activity-trace.js`](../scripts/activity-trace.js) | Frida. Starts with decoded task flags, arrivals with task placement and instance identity, a tiered caller-identity block, the result channel, and obscured touches. Complementary to `26-Intent/scripts/intent-monitor.js` and deliberately non-overlapping. |
| [`../examples/DeputyActivity.java`](../examples/DeputyActivity.java) | The vulnerable deputy, annotated with why a competent developer writes it. |
| [`../examples/DeputyActivityFixed.java`](../examples/DeputyActivityFixed.java) | The fixed counterpart, annotated with why each obvious half-fix fails. |
| [`../examples/build.sh`](../examples/build.sh) | Builds both lab APKs out of tree from SDK build-tools and a JDK. Handles the `INSTALL_FAILED_USER_RESTRICTED` case with a root fallback. |
| [`../labs/lab-01-read-the-task-graph.md`](../labs/lab-01-read-the-task-graph.md) | Derive all four launch modes from evidence. |
| [`../labs/lab-02-task-hijacking.md`](../labs/lab-02-task-hijacking.md) | Prove or disprove the StrandHogg configuration on your own device. |
| [`../labs/lab-03-deputy-grant-laundering.md`](../labs/lab-03-deputy-grant-laundering.md) | Reach a non-exported Activity and read a non-exported provider, with a control for each. |
| [`../labs/lab-04-tapjacking-consent.md`](../labs/lab-04-tapjacking-consent.md) | Overlay, obscured tap, and the defence stopping it. Requires an **unlocked** device. |
| [`../labs/lab-05-ctf-the-understudy.md`](../labs/lab-05-ctf-the-understudy.md) | CTF chaining three primitives. |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [09 — Android App Internals](../../09-Android-App-Internals/README.md) | Introduces the four component types and defers the task model here. |
| [21 — App Sandbox](../../21-App-Sandbox/README.md) | uid isolation, and `SYSTEM_ALERT_WINDOW` as a special permission. |
| [23 — Permissions](../../23-Permissions/README.md) | `protectionLevel`, and why `android:permission` on an Activity can be worthless. |
| [24 — IPC](../../24-IPC/README.md) | Places Activity starts on the map of IPC mechanisms. |
| [25 — Binder](../../25-Binder/README.md) | The kernel identity stamp, demonstrated unforgeable — and why an Activity cannot use it. |
| [26 — Intent](../../26-Intent/README.md) | **The message.** Resolution, the twelve fields, the redirection primitive, `PendingIntent`, deep-link verification. 30 owns the component; 26 owns what arrives at it. |
| [27 — Content Providers](../../27-ContentProviders/README.md) | **What a laundered grant is worth.** 30 stops at the moment the grant is issued. |
| [32 — Manifest](../../32-Manifest/README.md) | **The declaration audit** from an APK. 30 contributes the runtime view no manifest can show. |
| [71 — OWASP Mobile](../../71-OWASP-Mobile/README.md) | Maps tapjacking and overlay findings to MASVS-PLATFORM-3. |
| [53 — Frida](../../53-Frida/README.md) | Getting `activity-trace.js` to run at all. |
| [28 — Services](../../28-Services/README.md) | Where an overlay window lives, and where a bound Service gets a real caller identity. |
| [29 — Broadcast Receivers](../../29-BroadcastReceivers/README.md) | The other manifest-declared entry point. |
| [31 — Fragments](../../31-Fragments/README.md) | Sub-screens; they have no task of their own. **Owns fragment injection**, the class where an exported Activity lets its caller choose which Fragment appears inside it. |
| 43 — WebView | Where deep-link data reaching an Activity most often terminates. |
