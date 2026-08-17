# 31 — Fragments: references

Annotated. Everything here was either read directly while writing the chapter or is the canonical
place to check a claim the chapter makes. Where a source is *wrong* about something this chapter
measured, the annotation says so — that is more useful than a bare link.

---

## AOSP source

Paths are from the AOSP tree and are stable. The **behaviour** claims beside them were verified
against the device's own `/system/framework/framework.jar` with `dexdump`, not against the browser.

| Path | Why you would open it |
|---|---|
| `frameworks/base/core/java/android/preference/PreferenceActivity.java` | The whole reflective path lives in one file: `onCreate` reads `:android:show_fragment`, `switchToHeader` dispatches, `switchToHeaderInner` calls `isValidFragment` and then `Fragment.instantiate`, and `startPreferencePanel`/`startWithFragment` are the in-app callers. |
| `frameworks/base/core/java/android/app/Fragment.java` | `instantiate(Context, String, Bundle)`, the `sClassMap` cache, and `setArguments`. Note the order: `isAssignableFrom` **before** `getConstructor().newInstance()`. |
| `frameworks/base/core/java/android/app/FragmentManager.java` | `FragmentManagerImpl`, `saveAllState`/`restoreAllState`, and the `FragmentState` `Parcelable` that carries a class name across a process kill. |
| `frameworks/base/core/java/android/app/BackStackRecord.java` | What a back-stack entry actually is: a list of `Op`s and their inverses. Read this before arguing about what Back does. |
| `frameworks/base/core/java/android/app/DialogFragment.java` | Why a `DialogFragment` has its own window, and therefore its own `FLAG_SECURE` state. |
| `frameworks/base/core/java/android/app/Activity.java` | `getFragmentManager()`, and the `onSaveInstanceState` path that carries Fragment state into the Activity's saved state. |
| `frameworks/base/core/java/android/view/WindowManager.java` | `LayoutParams.FLAG_SECURE` — a window flag, which is the whole answer to "how do I protect one Fragment?". |
| `frameworks/base/core/java/android/content/pm/ApplicationInfo.java` | `targetSdkVersion`, the field the gate branches on. |
| `fragment/fragment/src/main/java/androidx/fragment/app/FragmentFactory.java` | AndroidX: `loadFragmentClass`, `instantiate`, `isFragmentClass`. Read it, then disassemble it — the source and the bytecode disagree about where the type check happens. |
| `fragment/fragment/src/main/java/androidx/fragment/app/FragmentStateManager.java` | AndroidX: where state restoration hands a class name from saved state to the factory. |
| `fragment/fragment/src/main/java/androidx/fragment/app/Fragment.java` | AndroidX: the deprecated static `instantiate(Context, String, Bundle)`, which still delegates to `loadFragmentClass`. |

**How to read the version on your own device**, which is what this chapter did:

```bash
# host
adb pull /system/framework/framework.jar
python3 -B -c "import zipfile;z=zipfile.ZipFile('framework.jar');[open(n,'wb').write(z.read(n)) for n in z.namelist() if n.endswith('.dex')]"
$ANDROID_HOME/build-tools/35.0.1/dexdump -d classes3.dex | grep -A35 "name          : 'isValidFragment'"
```

---

## Official Android documentation

| Document | Why, and where to distrust it |
|---|---|
| [Fragments](https://developer.android.com/guide/fragments) | The current AndroidX-first guide. Complete on mechanics, silent on the security consequences of reflective instantiation. |
| [The Fragment lifecycle](https://developer.android.com/guide/fragments/lifecycle) | The state machine, including the separate *view* lifecycle that `getViewLifecycleOwner()` exists for. |
| [Fragment manager](https://developer.android.com/guide/fragments/fragmentmanager) | Transactions, the back stack, child managers. The one page to read before arguing about what `addToBackStack` does. |
| [Communicating with fragments](https://developer.android.com/guide/fragments/communicate) | `setFragmentResult`, and why `setTargetFragment` was deprecated. |
| [Saving UI states](https://developer.android.com/topic/libraries/architecture/saving-states) | What survives a configuration change versus a process death — the distinction §3.3 depends on. |
| [`PreferenceActivity`](https://developer.android.com/reference/android/preference/PreferenceActivity) | Deprecated at API 29, **still shipping and still functional on API 35**. `EXTRA_SHOW_FRAGMENT` and `isValidFragment` are both public API and both documented. The javadoc for `isValidFragment` says the subclass must "verify" — and nothing enforces it. |
| [Settings with `androidx.preference`](https://developer.android.com/develop/ui/views/components/settings) | The replacement. Note what it does **not** have: any Activity that loads a Fragment named by an Intent. |
| [`ViewModel` overview](https://developer.android.com/topic/libraries/architecture/viewmodel) | Scoping. An Activity-scoped `ViewModel` is shared with every Fragment in that Activity, injected ones included. |
| [Behaviour changes: apps targeting API 35](https://developer.android.com/about/versions/15/behavior-changes-15) | Where the platform's own account of the API 35 changes lives. The install floor is the item that matters here. |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | **The authoritative record for any CVE claim in this area.** Verify an identifier and its affected-version range here before citing it anywhere. |

---

## Research and background

| Work | Why |
|---|---|
| The 2013 disclosure of fragment injection in `PreferenceActivity`, from IBM's application-security research group | The origin of the bug class and the reason `isValidFragment` exists. Read it as history. Then check its reachability claims against README §3.9, because the *mechanism* half is unchanged and the *"legacy apps are automatically vulnerable"* half is now gated by an install floor that did not exist in 2013. |
| The `ysoserial` body of work on Java deserialisation gadget chains | The same defect in a different runtime: an attacker-chosen type name reaching a reflective constructor. README §4.5's ordering measurement is a gadget-hunting question, and the methodology transfers directly — the only difference is that here the classpath is the application rather than a library set. |
| "Towards Discovering and Understanding Task Hijacking in Android" — Ren, Zhang, Wang, Chen, Mao, USENIX Security 2015 | Cited by [30-Activities](../../30-Activities/README.md), and the model for how to write about a UI-level attack family whose exploitability is device-dependent rather than absolute. |

**On CVE identifiers.** This chapter deliberately cites none. Identifiers exist for specific vendor
instances of fragment injection, but a wrong identifier is worse than no identifier, and this
repository's rule is to describe the class rather than invent an ID. AOSP *file paths* are stable and
are cited freely above.

---

## OWASP

| Identifier | Relevance |
|---|---|
| **MASVS-PLATFORM-1** — the app uses IPC mechanisms securely | The headline control: an exported Activity with an unbounded type-name parameter. |
| **MASVS-PLATFORM-3** — the app uses the user interface securely | `DialogFragment` phishing inside the victim's own window, `FLAG_SECURE`, Recents snapshots. |
| **MASVS-AUTH-1** — authentication is enforced where it needs to be | The impact: injection is an authentication bypass whenever the gate is a *screen* rather than a *session check*. |
| **MASVS-CODE-4** — the app validates and sanitises untrusted input | The arguments `Bundle`, which a Fragment has every reason to trust and no reason to be able to. |
| MASTG — testing deep links; testing for sensitive functionality exposure through IPC | The procedures labs 01–03 are written to satisfy with evidence rather than with assertions. |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Maps these to the current MASVS structure. |

---

## Tooling

| Tool | Why, and the gotcha |
|---|---|
| `dexdump` (Android build-tools) | The workhorse of this chapter. `dexdump -d classes.dex` gives per-method disassembly with source line positions, which is how the crash stack and the bytecode were shown to agree. |
| `baksmali` (inside `apktool`'s jar) | `java -cp apktool.jar com.android.tools.smali.baksmali.Main d classes.dex -o out/`. **Use this, not jadx:** `jadx 1.5.3` on this machine produces no output for a bare `classes.dex`, exits 0, and hangs on a `.jar`. |
| `javap -c` (JDK) | The only way to see that AndroidX's generic cast is erased. Point it at the `classes.jar` inside `fragment-*.aar`. |
| `aapt2 dump xmltree --file AndroidManifest.xml <apk>` | Resolving a class to a manifest entry, which is how "is it exported?" gets answered. |
| `adb shell dumpsys activity <package>` | The live Fragment state: `Active Fragments`, `Added Fragments`, `mContainerId`, `mState`. This is the runtime evidence for a report. |
| `uiautomator dump` | Reading the victim's screen. **Runs as `shell`, not as an app** — record it as instrumentation, not as an attack step. |
| Frida | `scripts/fragment-trace.js`. Note that `frida-server` does **not** link on the API 35 AVD used here; see README §7.4. |

---

## This chapter's own artefacts

| File | What it is |
|---|---|
| [scripts/fragment-injection-scan.py](../scripts/fragment-injection-scan.py) | DEX-structure scanner. Parses `string_ids`, `type_ids`, `method_ids`, `class_defs`, `class_data` and the instruction stream, and reports **per method** where external input reaches a reflective Fragment loader. Also classifies every `isValidFragment` override by the set of methods it calls. Validated against this chapter's own victim APK before being trusted. |
| [scripts/preference-gate-probe.sh](../scripts/preference-gate-probe.sh) | Device probe: is the reflective path present on this build, what `targetSdk` threshold is compiled into the gate, what is the install floor, and which installed packages sit below it. |
| [scripts/pull-apk-corpus.sh](../scripts/pull-apk-corpus.sh) | Builds the corpus and reports the **denominator**, the failures by name, and the STORED/DEFLATED split. Refuses to write inside the repository. |
| [scripts/fragment-trace.js](../scripts/fragment-trace.js) | Frida: the gate, both loaders, both transaction classes, `setArguments`, a filtered `ClassLoader.loadClass`, and every Activity's extras. **Reviewed and unrun** — labelled in its own header and in README §7.4. |
| [examples/build.sh](../examples/build.sh) | No-Gradle APK build at any `TARGET_SDK`, out of tree. |
| [examples/README.md](../examples/README.md) | The `[Vn]` / `[Hn]` tag table mapping every vulnerability and every fix to its file, plus the ten named attacks. |
| [examples/04-hardening-a-settings-screen.kt](../examples/04-hardening-a-settings-screen.kt) | `[H3]` — the migration off `PreferenceActivity`, with a closed route enum and a destination-side check. Reviewed, not compiled; its header says why. |
| [examples/05-enterprise-fragment-router.kt](../examples/05-enterprise-fragment-router.kt) | `[H4]` — a sealed route table with per-route `allowExternal` and `requiresSession`, observable refusals, and a CI assertion. |
| [labs/lab-01-land-the-injection.md](../labs/lab-01-land-the-injection.md) | Reproduce the classic end to end from an app uid, with controls, read three ways. |
| [labs/lab-02-is-it-still-exploitable.md](../labs/lab-02-is-it-still-exploitable.md) | Read the gate out of your own device, find your install floor, reach all three gate states. |
| [labs/lab-03-beyond-preferenceactivity.md](../labs/lab-03-beyond-preferenceactivity.md) | The same bug class without `PreferenceActivity`; extra, deep link, arguments, and the type-check ordering. |
| [labs/lab-04-sweep-and-adjudicate.md](../labs/lab-04-sweep-and-adjudicate.md) | Sweep your own device and account for every hit. |
| [labs/lab-05-ctf-the-second-cast.md](../labs/lab-05-ctf-the-second-cast.md) | CTF: two flags, one deliberate dead end, and a debrief about severity. |
| [cheatsheet.md](../cheatsheet.md) · [mindmap.md](../mindmap.md) · [faq.md](../faq.md) | Dense reference, the full mind map, and the questions learners actually ask. |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | The uid isolation an injected Fragment does **not** cross, and therefore the ceiling on its impact |
| [23-Permissions](../../23-Permissions/README.md) | Why there is no permission on a Fragment, and what the host's `android:permission` is worth |
| [24-IPC](../../24-IPC/README.md) | **The Bundle.** §3.18 owns nested Intents, arbitrary `Parcelable`s and the API 33 typed getters; this chapter starts where it stops |
| [25-Binder](../../25-Binder/README.md) | The kernel identity stamp, demonstrated unforgeable, and why it is gone by the time a Fragment exists |
| [26-Intent](../../26-Intent/README.md) | **The message.** Resolution, deep links, `intent:` URIs, and the claim that an Intent carries no caller identity |
| [27-ContentProviders](../../27-ContentProviders/README.md) | Where an injected Fragment's data often lives |
| [30-Activities](../../30-Activities/README.md) | **The host.** The Activity lifecycle, tasks, exported components, tapjacking. 30 owns the screen; 31 owns what is inside it |
| [32-Manifest](../../32-Manifest/README.md) | **The declaration audit**, which lists hosts and cannot list Fragments |
| [33-Storage](../../33-Storage/README.md) | Where persisted Fragment state and arguments end up |
| [42-R8](../../42-R8/README.md) | Why reflective Fragment loading and minification are in direct conflict, and what a keep rule tells you |
| [43-WebView](../../43-WebView/README.md) | The most valuable injection destination, and the `[Vn]`/`[Hn]` example convention this chapter copies |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | The funnel discipline §8.4 applies: a sweep produces leads, not findings |
| [56-JADX](../../56-JADX/README.md) | Why the decompiled gate is evidence toward a finding and the Smali is the finding |
| [64-Xposed](../../64-Xposed/README.md) | The corpus-sweep methodology and the "explain every hit" rule, on the same device and the same image |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Maps these findings to the current MASVS structure |
