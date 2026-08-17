# 66 — Instrumentation · FAQ

Real questions, including the ones people are embarrassed to ask. Answers marked **[measured]** were
established on `sdk_gphone16k_x86_64`, Android 15 / API 35, `userdebug`; the rest are
documentation-derived and say so.

---

### 1. The word "instrumentation" is used for two completely different things. Which one is this?

The platform class `android.app.Instrumentation` and the `<instrumentation>` manifest element — the
mechanism behind `am instrument`, `androidx.test`, Espresso and every Android CI pipeline.

The other sense — attaching to a running process and rewriting it from outside — is Frida's, and it
belongs to [53 — Frida](../53-Frida/README.md) and [65 — Hooking](../65-Hooking/README.md). The two
share an ambition (your code where the target's code runs) and share almost nothing else.

### 2. Is this a vulnerability?

No. It is a platform feature working exactly as designed, and writing "the app can be instrumented"
in a report will cost you credibility for the findings that are real. What is assessable is the
*artefact* — a test APK that escaped, test code left in a release build, a signing relationship
nobody meant to create, a test back door still reachable. See README §5.9.

### 3. Does the app have to be `android:debuggable="true"`?

**No. [measured]** A release build with `flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]` — no `DEBUGGABLE`
— was instrumented, its `SharedPreferences` read and a private static field rewritten. This is the
most widely repeated wrong answer about the subject.

`debuggable` does gate `run-as`, JDWP debugger attach and `adb backup` of app data, which is why the
mistake is so persistent: it is the right answer to three neighbouring questions.

### 4. So what *is* required?

**The test package and the target must be signed by the same certificate — or the caller must be
root. [measured]** The refusal names the check:

```
Permission Denial: starting instrumentation ComponentInfo{...} from pid=N, uid=2000
  not allowed because package <test> does not have a signature matching the target <target>
```

Root bypasses it; the shell (uid 2000) does not.

### 5. Can I instrument an app I did not build and cannot re-sign, on a device without root?

No. That is the honest boundary of the technique. Go and read
[53 — Frida](../53-Frida/README.md), or find a way to repackage the app — at which point you can
sign both with your own key and instrumentation is open again.

### 6. `INSTRUMENTATION_CODE: -1` — did it fail?

It succeeded. `-1` is `android.app.Activity.RESULT_OK`. `RESULT_CANCELED` is `0`. Everybody misreads
this once, and a CI gate written as "fail unless the code is zero" inverts the meaning of every run
it ever sees.

### 7. Why does the app restart when I run an instrumentation?

**Because `ActivityManagerService` force-stops it, twice. [measured]** Once before starting, once
when `finishInstrumentation` arrives:

```
I ActivityManager: Force stopping <pkg> appid=<n> user=0: start instr
I ActivityManager: Force stopping <pkg> appid=<n> user=0: finished inst
```

Any session, any navigation state, any in-memory cache is gone at both ends. This is the sharpest
practical difference from attaching with Frida, which preserves the live process.

### 8. Can I keep the process alive instead of losing it every run?

Yes: **do not call `finish()`.** `Instrumentation.finish()`'s own javadoc says it "will cause the
application process to exit". Keep the instrumentation thread alive — a loop, a socket listener, a
`CountDownLatch` — and you have a long-running agent inside the target instead of a one-shot. You
still pay the force-stop at the *start*.

### 9. What is the difference between `getContext()` and `getTargetContext()`?

`getContext()` is the **test** package's context. `getTargetContext()` is the **target's**. Storage,
resources, `ApplicationInfo` and `getFilesDir()` all differ.

Using the wrong one is the single most common beginner error in the subject, and it fails silently:
you read the test package's empty `SharedPreferences` and conclude the app stores nothing.

### 10. How early does my code actually run?

**After the `Application` constructor, after `attachBaseContext()`, and after every
`ContentProvider.onCreate()` — but before `Application.onCreate()`. [measured]**

The framework's own javadoc says *"before any application code has been loaded"*, and that is wrong:
`ActivityThread.handleBindApplication()` calls `makeApplicationInner()` and
`installContentProviders()` above the `mInstrumentation.onCreate(...)` call site, in the same method,
in the same file.

### 11. Does that matter, or is it trivia?

It decides your tool. Commercial packers unpack in `attachBaseContext`; `androidx.startup`, Firebase
and most crash reporters initialise in a `ContentProvider`. **All of that has already happened when
you arrive.** Anything in `Application.onCreate()` or later, you are ahead of.

If the check you need to defeat lives in one of the first two slots, you need Frida's spawn-and-hold
(`frida -U -f`) or a Zygote-level framework ([63 — LSPosed](../63-LSPosed/README.md)).

### 12. How does my test code call the target's classes without a compile-time dependency?

**The test APK's DEX is first on the target's own class path. [measured]** `ActivityThread` builds
the instrumentation's `LoadedApk` with the app context's class loader as parent, and the app's loader
already lists both APKs. So `Class.forName("com.example.Thing", true, getContext().getClassLoader())`
resolves.

### 13. Then can I just add the target's classes to my test APK and import them normally?

**Do not.** Your DEX is first, so a class you ship with the same fully-qualified name **shadows** the
target's. Every static field you then read is *your copy's*, initialised to its default; every result
you publish is a confident lie, and nothing warns you. Reflect, always. Chapter §11.2.

If you need compile-time types for your IDE, add them as `compileOnly` / `provided` so they are not
packaged.

### 14. Can an ordinary app — not the shell — start an instrumentation?

**Yes. [measured]** Two of `am`'s defaults get in the way first, and neither is the gate:

```
--user current  ->  resolves to -2, needs INTERACT_ACROSS_USERS_FULL.  Pass --user 0
test-API access ->  enabled by default, needs DISABLE_HIDDEN_API_CHECKS.  Pass --no-test-api-access
```

With both cleared, an app UID succeeded. The signature relationship still applies, so the realistic
case is **co-signed sibling packages** — a vendor's "diagnostics" or "companion" APK.

Bound on the measurement: the caller was the target package's own UID, so this shows
self-instrumentation from an app UID. Instrumenting a *different* co-signed package was not measured.

### 15. Is the app told that it is being instrumented?

Not by a callback, but it can ask, and the whole check is one line:

```java
List<InstrumentationInfo> aimed =
        ctx.getPackageManager().queryInstrumentation(ctx.getPackageName(), 0);
```

A non-empty list means a test APK aimed at this package is installed. Almost nothing in the wild does
this, which is a large part of why the technique is worth knowing.

### 16. Can I hide from that check?

Not from the *installed* half. The `<instrumentation>` node cannot be removed — the package manager
reads it and the binding is the whole mechanism — and `pm list instrumentation` shows it. You can
attack the check itself once you are inside the process, but that is a delaying action against
something running in a process you already own; see
[67 — Bypassing Protections](../67-BypassingProtections/README.md).

### 17. Is `am instrument` quieter than Frida?

On disk, yes: no server binary, no injected library in `/proc/<pid>/maps`, no listener on 27042,
nothing under `/data/adb`. A detection suite tuned for Frida and LSPosed sees a clean device.

In the package manager, no: your test APK is a visible installed package with a visible
instrumentation row. And in `system_server`'s log, no: the two `Force stopping … instr` lines are
emitted by the system, not the app, and an attacker inside the app cannot suppress them. It is a
trade, not a win.

### 18. What is `AndroidJUnitRunner`, then?

An `Instrumentation` subclass, shipped inside the test APK, that discovers and runs JUnit tests. It
has **no privilege the platform class lacks**. The chapter's `VaultProbe` is 240 lines of platform API
and the framework cannot tell them apart. When you find `AndroidJUnitRunner` in an APK you have found
a convention, not a capability.

### 19. What does `--no-hidden-api-checks` actually change?

It lifts non-SDK interface restrictions for that process. **Measured by census, because a single
lookup is worthless:**

| Class | default | with the flag |
|---|---|---|
| `android.app.ActivityThread` | 30 methods | **289 methods** |
| `dalvik.system.VMRuntime` | 23 methods, `setHiddenApiExemptions` invisible | 72 methods, **visible** |

Both `SystemProperties.get` and `ServiceManager.getService` succeeded **with enforcement on**, because
they are greylisted rather than blocklisted. A probe testing only those two would report "hidden API
is not enforced" and be wrong.

### 20. Can I run shell commands from inside an instrumentation?

Yes, and this is the most surprising result in the chapter. `getUiAutomation().executeShellCommand()`
runs the command as **uid 2000**, from a process whose own UID is the app's. **[measured]**
`/data/local/tmp`, `/system/xbin/su` and `/proc/modules` — all `EACCES` to the process's own reads —
all came back through that channel in the same run.

**And that is a trap.** If you write a detection probe as an instrumentation and reach for
`executeShellCommand` because it is convenient, you have measured the *shell's* vantage and nothing
in your output says so. The app you are assessing has no `UiAutomation`.

### 21. My `executeShellCommand` with a pipe returns nothing and no error.

It is not a shell. **[measured]** `echo "one two"` returns `"one two"` **with the quotes**;
`getprop | wc -l` returns nothing at all. The string is split on whitespace and executed. No quoting,
no pipes, no redirection, no globbing, and no diagnostic. Verify that your output is non-empty,
because empty is what failure looks like.

### 22. All my `read.*` values come back empty. Does the app store nothing?

Probably not — you are probably racing it. `onStart()` runs on a thread that starts immediately from
`onCreate()`, while `ActivityThread` proceeds to `Application.onCreate()` on the main thread. Read the
app's storage before the app writes it and you get `ENOENT`, a passing exit code, and a conclusion
that looks like a finding.

This happened during the writing of this chapter. The probe waited for a marker set on *entry* to
`Application.onCreate()` and read four empty channels. **Waiting for a flag raised at the start of the
work is waiting for nothing.** Wait on a completion marker, or read in a *second* run after the app
has started once.

### 23. Why does `pm list instrumentation` show nothing on my device?

Because a stock image genuinely has none. **Measured: zero rows on an Android 15 GMS AVD with 247
packages installed.** That is a useful baseline rather than a disappointment — it means every row you
ever see was put there by somebody.

It also means the command is nearly useless for the *interesting* question, which is residue.

### 24. What is "residue" and why do I care more about it?

Test-harness code that shipped inside an ordinary APK with **no** `<instrumentation>` node. It cannot
be found by `pm list instrumentation` and it is much more common than declared instrumentations.

Measured example: a 38-APK sample from the AVD returned one `DECLARED` (this chapter's own probe) and
one `RESIDUE` — the Magisk manager, a release, R8-minified APK carrying three un-minified JUnit test
classes under `com/topjohnwu/magisk/test/`. Their string constants name the exact command line that
triggers its root-request UI. Rated **Informational** because Magisk is open source and nothing
sensitive leaks; the *class* of finding is what matters. README §6.4 walks the adjudication.

### 25. Why does residue survive obfuscation?

Because test frameworks need reflection, so they attract `-keep` rules. A rule like
`-keep class **.test.**` preserves the test classes with their original names — inside a build where
everything else became `t4/b`. The consequence people miss: **un-minified test classes name minified
production ones**, so residue partially undoes the obfuscation of everything the tests touched.

### 26. Is `android:testOnly="true"` a security control?

No. **[measured]** A plain install is refused with
`INSTALL_FAILED_TEST_ONLY: Failed to install test-only apk. Did you forget to add -t?`, and
`adb install -t` succeeds. Once installed it is an ordinary package that appears in
`pm list instrumentation` and instruments normally. It protects a distribution channel, not a device.

### 27. What is the single best defence a developer can ship?

**Sign test APKs with a different key from the release key.** It does not break
`connectedAndroidTest` on a CI device farm, and it removes the entire "co-signed test APK escapes
into the wild" path at a stroke. Second best: do not publish the test APK beyond the device farm.
Third: the one-line `queryInstrumentation` self-check, as telemetry rather than as a gate.

### 28. If I flip a boolean in the app, does the app really see it?

**Yes, if the app reads that boolean rather than recomputing the decision. [measured]**
`LicenseGate.sPremium` was set `true` by reflection and the app's own `isPremium()` — invoked, not
re-read — returned `true`. Same process, same heap, same field.

If the app recomputes from a server response or a syscall on every call, changing a stored value
achieves nothing and you need [65 — Hooking](../65-Hooking/README.md). That is the difference between
changing what a process **contains** and changing what a method **does**.

### 29. Can I install a hook from an instrumentation?

Yes, and pure Java gets you further than people expect. `java.lang.reflect.Proxy` over an
interface-typed static field intercepts everything routed through it — which in a modern app means
Retrofit services, OkHttp interceptors, analytics sinks and DI graph entries.
`examples/HookFromInstrumentation.java` does exactly that, installed during `onCreate()`, and catches
the app's first event. **[measured]**

For a final class, a static method or a native call, load a `.so` from your test APK and everything
in [65 — Hooking](../65-Hooking/README.md) applies. Instrumentation is the delivery vehicle.

### 30. Do I need Gradle to build a test APK?

No, and building without it is the fastest way to understand the mechanism. Six commands:
`aapt2 link`, `javac`, `d8`, zip in the `classes.dex`, `zipalign`, `apksigner`.
`examples/build-instrumentation-fixtures.sh` is a working, commented implementation that also builds
the four variants the chapter's gate matrix needs.

### 31. `adb shell su -c 'am instrument ...'` says my device is not rooted. Is it? <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted in the question this FAQ entry answers -->

Probably yes. Two things break that command at once: the outer shell strips the quotes so `su` sees
the arguments split apart, and the AVD's AOSP `su` rejects `-c` with `su: invalid uid/gid '-c'` —
which reads exactly like "not rooted". Use `adb shell "su 0 <command>"`. Check with
`adb shell "su 0 id"` first. Magisk's `su` does accept `-c`; use whichever form returns uid 0.

### 32. My run says `Unable to instantiate instrumentation`.

Your class needs a **public no-argument constructor**. `ActivityThread.initInstrumentation()` calls
`cl.loadClass(name).newInstance()`. An inner class, a non-public class, or one with only a
parameterised constructor all fail here. This is the second most common first-run failure after a
signature mismatch.

### 33. My run says `Unable to find instrumentation info for ...`.

The component you named is not a **declared** `<instrumentation>` node. `am instrument` looks it up
through `PackageManager`, not through the class loader, so a class that exists in the DEX but is not
in the manifest cannot be started. Copy the exact string from `adb shell pm list instrumentation`.

### 34. The command returns instantly and prints nothing useful.

You omitted `-w`. Without it `am` does not wait and the results arrive after it has exited. Add `-r`
too, or the protocol is decoded into a human-readable stream you cannot parse.

### 35. How do I pass data in and get data out?

In: `-e NAME VALUE`, repeatable, strings only, delivered as the `Bundle` in `onCreate`. Out:
`sendStatus()` for progress, `addResults()` for durable results, `finish()` for the final bundle —
**plus logcat**, which is the only channel that survives a crash. Emit every finding twice.

### 36. Can one instrumentation target two apps?

No. One `targetPackage` per `<instrumentation>` node. You can install several test APKs, or use
`UiAutomation` for cross-app *UI* driving — which is what `androidx.test.uiautomator` does, and why
it works across app boundaries when Espresso does not.

### 37. What is `android:targetProcesses="*"` for?

A multi-process app normally exposes only its main process to an instrumentation.
`targetProcesses="*"` loads your code into **any** process that runs the target's code — which for a
large app can be five or six processes with quite different loaded state. Added in API 26.

### 38. How would a forensic analyst know this was used?

Better than for most techniques, because everything goes through the package manager and
`system_server`:

- an installed test package with an `<instrumentation>` node naming its target;
- the two `Force stopping … : start instr` / `: finished inst` lines in logcat, timestamped;
- app-ops attributed to the **target** package, because the instrumentation's op package name is the
  target's;
- `/sdcard/instrument-logs/` if `am instrument -f` was used without a path;
- the test package's own `/data/data/<test-pkg>`, which attackers routinely forget to clean.

### 39. Which chapter do I read next?

If you want the interception mechanisms: [65 — Hooking](../65-Hooking/README.md). If you want the
same goal from outside the process: [53 — Frida](../53-Frida/README.md). If you want the framework
that reaches every process: [63 — LSPosed](../63-LSPosed/README.md). If you want the discipline that
makes any of it into evidence: [51 — Dynamic Analysis](../51-DynamicAnalysis/README.md).

### 40. Everything here was measured on one emulator. How much should I trust it?

Read the labels. Rows in the gate matrix that end in a **refusal** are solid — a permissive
`userdebug` build cannot manufacture a refusal. The matching-signature successes are the documented,
supported path. The **root-bypass** rows and the app-UID row are upper bounds and should be re-run on
a `user` build before you rely on them; the chapter says so in §3.9 rather than quietly presenting
them as settled. No second device was attached while this chapter was written, and that gap is stated
rather than papered over.
