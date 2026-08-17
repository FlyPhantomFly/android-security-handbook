# 07 — AOSP FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

### 1. Is AOSP the same thing as "Android"?

No, and the gap is where most of your work will be. AOSP is the published source of the operating
system. A retail phone runs AOSP **plus** Google Mobile Services (Play Store, Play services, Play
Integrity, Play Protect), **plus** the manufacturer's modifications to the framework and their
preinstalled apps, **plus** the chipset vendor's binary drivers, HAL implementations and firmware. Only
the first of those four is open. The other three are where a large majority of device-specific
vulnerabilities live.

---

### 2. Why can I not just `git clone` AOSP?

Because it is not one repository. It is roughly a thousand of them, and there is no single git object
graph containing all of it. `repo` is a Python program that reads an XML manifest listing every project,
its remote, where it goes in the tree and which revision to check out, and then drives `git` once per
project. Every directory in the result *is* a normal git repository, so `git log`, `git blame` and
`git show` all work once you are inside one.

---

### 3. How big is a checkout, really?

Around 100 GB for the source with `--depth=1`, and considerably more with full history. A build adds
150–250 GB in `out/`. Budget 400 GB of SSD, and expect the first `repo sync` to take hours. If you only
want to *read*, you do not need any of this — `cs.android.com` is faster, always current, and has
cross-references a local grep cannot match.

---

### 4. Do I actually need a local checkout at all?

For most work, no. Reading is better in Code Search: it has cross-references, blame, history, and it
indexes multiple branches. You need a local checkout for four things: `git log -S` to find the commit
that introduced or removed a string, cross-release diffing, complex multi-pattern searches with
`ripgrep`, and anything in a vendor tree, which is not indexed anywhere. And obviously for building.

---

### 5. I found a method in AOSP that does not exist in Android Studio. What?

You found a `@hide` method. `@hide` is a Javadoc annotation that excludes a class or member from the
generated SDK stubs, so it is absent from `android.jar` and the IDE will not offer it. The method exists
at runtime and is reachable by reflection — subject to hidden-API enforcement from Android 9 onward. See
question 12.

---

### 6. What actually is `android.jar`?

A **stub** jar. It contains every public class and method signature, with bodies that are literally
`throw new RuntimeException("Stub!");`. It exists so `javac` can type-check your code. At runtime, the
real implementation comes from the device's boot classpath. Prove it:

```bash
javap -c -p -cp $ANDROID_HOME/platforms/android-35/android.jar android.content.Context | head -20
```

There is one per API level in `prebuilts/sdk/<n>/public/android.jar`, and there are parallel system,
test and module-lib variants.

---

### 7. What is `@SystemApi` and why do I care?

It is an annotation that puts a member into the *system* SDK stubs rather than the public ones. System
APIs are intended for privileged apps — OEM apps, carrier apps, device-owner apps — and are usually
additionally gated by a `signature` or `signature|privileged` permission. You care because when you
decompile a preinstalled application and find calls you do not recognise, searching
`frameworks/base/core/api/system-current.txt` for the name tells you whether you have found a privileged
capability. If you have, the next question is which permission gates it and whether an unprivileged app
can reach it through the preinstalled app's own exported components.

---

### 8. Where do I even start when I want to trace an API?

Name a symbol you know is involved, then follow six steps:

1. Find its declaration. The SDK class is usually **abstract** — `Context`, `SharedPreferences`,
   `PackageManager`.
2. Find the implementation — `ContextImpl`, `SharedPreferencesImpl`, `ApplicationPackageManager`.
3. Read the method body and see where it goes.
4. If it crosses a process boundary, it will call `SomethingManager.getService()` — find the `.aidl`.
5. Search for `extends I<Name>.Stub`. That class is the server, and it is in `system_server`.
6. Inside it, find `Binder.getCallingUid()`. That is where the real decision is made.

That procedure has worked on every Android release for a decade. Memorise it rather than memorising
where any particular class lives, because classes move and the procedure does not.

---

### 9. Why does the AOSP source not match what my device does?

Four possibilities, in order of likelihood:

1. **You are reading the wrong branch.** Code Search defaults to `main`. Read
   `getprop ro.build.fingerprint`, map the build ID to an AOSP tag, and switch the branch selector.
   This is by far the most common cause.
2. **The OEM forked that class.** Apache 2.0 imposes no publication obligation, so their version is not
   anywhere. Decompile `services.jar` and diff against AOSP for the matching tag.
3. **It is a Mainline module at a different version than the platform release.** Components like the
   permission controller, ART, DNS resolver and media provider update through Play independently.
4. **An `overlay` or `config.xml` value was changed.** Many platform behaviours are driven by resource
   values an OEM can override without touching code.

---

### 10. Why does hooking `checkSelfPermission` not let me use the camera?

Because `checkSelfPermission` is an **advisory query** running in your own process, and your own process
is not a security boundary. The real check happens on the far side of Binder, inside the service that
owns the camera, against the calling UID that the **kernel** stamped into the transaction in
`binder_transaction()`. That service has never heard of your hook.

Client-side permission hooks are useful for exactly one thing: making an app's *own* code take the
permitted branch so you can analyse it. They grant nothing. To actually get a permission you change the
state in `system_server` (`pm grant`, which requires privilege) or you exploit something.

---

### 11. Then where *is* the app sandbox?

In three independent places, none of them in your process:

- **Unix DAC.** Each app gets a distinct UID at install; its data directory is owned by that UID and the
  kernel enforces the file permissions.
- **SELinux MAC.** Each app runs in a domain (`untrusted_app` and relatives) and `system/sepolicy/`
  constrains what that domain may do, independently of UID.
- **The binder driver.** `drivers/android/binder.c` stamps every transaction with the sender's
  credentials, taken from the sending task, so services can authorise against an identity the caller
  cannot forge.

---

### 12. What is the hidden-API blocklist and how do I turn it off?

From Android 9, ART restricts reflective and JNI access to non-SDK framework members. Four lists: SDK
(allowed), unsupported (allowed but logged), max-target-X (allowed only if your `targetSdk` is at or
below X), and blocked (always denied). Enforcement is in `art/runtime/hidden_api.cc`, on the reflection
and JNI lookup paths.

```bash
adb shell settings put global hidden_api_policy 1     # JUST_WARN — the research setting
adb shell settings put global hidden_api_policy 0     # DISABLED
adb shell settings delete global hidden_api_policy    # back to default
```

Three things people get wrong about it. It works on **retail** devices over plain adb, because the shell
UID holds `WRITE_SECURE_SETTINGS` — you do not need root or a userdebug build. It is **global** and
**persists across reboots**, so reset it before handing a device back. And it changes app behaviour, so
record the value in your evidence exactly as you record the Android version.

---

### 13. Why does a hidden-API denial look like a completely unrelated bug?

Because it throws the ordinary reflection exception — `NoSuchMethodException`, `NoSuchFieldException` —
rather than anything named "denied". An app that catches those broadly and falls back will simply behave
differently with no visible cause. `logcat | grep -i "Accessing hidden"` shows you what actually
happened.

---

### 14. What is the difference between `check*Permission` and `enforce*Permission`?

`check*` returns an `int` that the caller may ignore. `enforce*` throws `SecurityException`. In an audit,
every `checkCallingPermission` call site deserves a look at what happens to the return value — an ignored
or mishandled result is a permission bypass, and it is invisible from the app side.

---

### 15. What is `clearCallingIdentity` and why do you keep bringing it up?

`Binder.clearCallingIdentity()` makes subsequent `Binder.getCallingUid()` calls return the *system's*
UID rather than the caller's, so a service can do privileged work on its own behalf. It is legitimate and
used constantly.

The bug pattern is a permission check placed **after** the clear. It then validates the system's
identity, and passes for everybody. It is a textbook confused deputy, it is reachable by any app with no
permissions, and the grep is two lines:

```bash
rg -n -A25 "clearCallingIdentity" frameworks/base/services/core/java | grep -E "checkCalling|enforceCalling"
```

It works just as well on a decompiled OEM `services.jar`, and that is where you will actually find it,
because vendor code receives far less review than AOSP.

---

### 16. What is app-ops? Nobody ever explains it.

A second permission layer that sits *beside* the permission system, per package and per operation. An
operation can be `allow`, `ignore`, `deny`/`errored`, or `default` (fall back to the permission check).
Many dangerous permissions have a paired app-op and **both** must permit the operation.

The important part is that `ignore` fails **silently**: the API call succeeds and returns nothing — an
empty location, an empty contact list, an empty clipboard — rather than throwing. So an app can have
`CAMERA` granted and still get nothing. When an API returns empty data unexpectedly, check app-ops before
you conclude anything:

```bash
adb shell appops get com.example.app
adb shell appops set com.example.app COARSE_LOCATION ignore
```

It is also the better way to test how an app degrades under partial permission, because it reproduces the
silent failure mode real users hit and developers almost never handle.

---

### 17. Should I build AOSP, or is it a waste of time?

Build it if you do platform work; skip it if you only test applications. The specific value of a
self-built `userdebug` image is that it gives you, simultaneously: `adb root` and a writable `/system`
with no Magisk in your trusted computing base; source that matches the running binary exactly; unstripped
symbols for every native binary in `out/target/product/<device>/symbols/`; the ability to *patch the
operating system* so your instrumentation is below anything an app can hook; `m snod` for a one-minute
patch-flash-test loop; and SELinux still enforcing, so what you observe is representative. Nothing else
gives you all of that at once.

---

### 18. Which build target should I pick?

`aosp_cf_x86_64_phone-trunk_staging-userdebug`. Cuttlefish is AOSP's virtual reference device: it runs on
your workstation, needs no hardware, boots the real system image you built, and supports `adb root` on a
userdebug build. Use a real Pixel target only when you need real HALs or a real TEE.

---

### 19. What exactly does `m snod` do, and why does everyone mention it?

"System, No Dependencies." It repacks `system.img` from whatever is currently in
`out/target/product/<device>/system/`, **without** re-deriving whether those files were legitimately
produced by the tree. After one full build you can change one file, run `m <module>` to rebuild it, then
`m snod`, and have a flashable image in under a minute. That loop is what makes platform research
practical.

The corollary matters too: an `out/` directory someone else gave you is untrusted, because it may contain
files that no source in the tree produced.

---

### 20. Why does my app behave differently on my AOSP build than on a real phone?

Almost always because AOSP has no Google Mobile Services. Any code path touching
`GoogleApiAvailability`, Firebase, SafetyNet or Play Integrity behaves differently — usually failing, and
sometimes failing *open*, which is the dangerous case: a root-detection or integrity check may appear to
be bypassed when in fact the component that would have caught you was never installed. Develop on AOSP
because you can read and patch it; **confirm on a retail device**.

---

### 21. Can I put GMS on my AOSP build?

Redistributing Google Mobile Services requires a licence, and various community packages exist for
custom ROMs with legally murky provenance. For professional work the answer is: do not fight it. Keep an
AOSP device for understanding and patching, and a retail device with a genuine GMS build for validating
findings. That separation is also better methodology — it forces you to distinguish "this is how the
platform works" from "this is what happens on the device the user has".

---

### 22. What is Treble and why does it keep coming up?

Project Treble (Android 8) separated the platform from the vendor implementation with a versioned,
stable interface — the HALs declared in `hardware/interfaces/`. Before it, upgrading Android meant the
silicon vendor rewriting their code. After it, `system.img` and `vendor.img` can be updated
independently. That is why Generic System Images work, and it is why the two security patch levels
(`ro.build.version.security_patch` and `ro.vendor.build.security_patch`) exist as separate properties
and routinely differ by months.

---

### 23. What is Mainline?

A set of platform components — the permission controller, ART, DNS resolver, media codecs, MediaProvider,
Wi-Fi, Bluetooth, adb and more — packaged as APEX or APK modules that Google updates through Google Play
System Updates, independently of the OS release. It shortens the patch window for those components
dramatically, because it bypasses the OEM entirely.

For you it means two devices on the same Android version can have materially different behaviour in
those components, so record the module versions:

```bash
adb shell pm list packages --apex-only
```

---

### 24. Which security patch level should I trust?

Neither, on its own. Read both:

```bash
adb shell getprop ro.build.version.security_patch      # system partition
adb shell getprop ro.vendor.build.security_patch       # vendor partition
```

They routinely differ by many months, and the vendor partition is where the camera, modem, GPU and DSP
HALs live — which is where the severe device-specific bugs are. A device advertising a current system
patch level with a year-old vendor partition is a legitimate, reportable finding, and it takes ten
seconds to check.

Also remember both are just strings in `build.prop`. They are a claim, not evidence.

---

### 25. What is patch gapping?

AOSP security fixes are public git commits, and the monthly bulletin links them. An attacker who reads
the diff frequently has the bug — a two-line bounds check tells you precisely what was unbounded.
Meanwhile the fix must traverse the OEM's integration, the silicon vendor's BSP and carrier testing
before reaching a user, which takes weeks to months. That window is one of the most reliable ways to
compromise Android devices in practice.

---

### 26. What is CTS, and can I use it?

The Compatibility Test Suite: thousands of automated tests, published in `cts/`, that a device must pass
to be called Android-compatible and to license GMS. You can run it, and you should know that
`cts/tests/tests/security/` encodes specific security requirements as executable tests. A device failing
a security CTS test is failing a defined, Google-published requirement, which is a much stronger position
in a report than "we think this is weak".

```bash
cts-tradefed run commandAndExit cts --module CtsSecurityTestCases
```

---

### 27. What is the difference between CTS, VTS, GTS and STS?

CTS tests API and platform behaviour and is public. VTS tests the *vendor* interface — HAL conformance,
kernel configuration, Treble requirements — and is public. STS checks that specific security bulletin
patches are actually applied. GTS tests GMS behaviour, is required for GMS licensing, and is **not**
published.

---

### 28. Someone gave me a vendor's source tree. What do I read first?

Three things, in this order:

1. `.repo/manifests/default.xml` — which AOSP release is this based on, and which remotes other than
   `android.googlesource.com` supply code?
2. `.repo/local_manifests/*.xml` — what was added or replaced locally? This is where surprises live.
3. `repo manifest -r` output — is anything on a mutable branch rather than pinned to a SHA? If so, nobody
   can say precisely what was built.

Then `rg -n "extends I[A-Za-z]+\.Stub" vendor/ device/` to enumerate the vendor's added Binder services,
and check each one for permission enforcement.

---

### 29. How do I find what an OEM added to a device when I have no source?

Diff behaviours rather than code.

```bash
# On the target device
adb shell service list | awk '{print $2}' | sort > oem.txt
# On a stock Pixel or Cuttlefish of the SAME Android release
adb shell service list | awk '{print $2}' | sort > aosp.txt
comm -23 oem.txt aosp.txt
```

Everything in the output is a vendor-added system service, running as UID 1000, reachable over Binder,
and never reviewed by Google. It takes two minutes and it is the single most productive first step on an
OEM engagement.

---

### 30. I decompiled `services.jar` and it is nearly empty. Why?

On modern devices the real code is pre-compiled and lives in
`/system/framework/oat/<arch>/services.vdex`, with the jar reduced to a shell. Extract the DEX first:

```bash
adb shell oatdump --vdex-file=/system/framework/oat/arm64/services.vdex \
                  --export-dex-to=/data/local/tmp/svc
adb pull /data/local/tmp/svc
jadx -d svc-src svc/*.dex
```

See [13-ART](../13-ART/README.md) §6.2.

---

### 31. What is `out/target/product/<device>/symbols/` and why is everyone excited about it?

Unstripped copies of every native binary and library on the image, with full symbol tables and often
DWARF debug information. Load *those* into Ghidra or IDA instead of the stripped on-device versions, and
weeks of reversing collapse into an afternoon. If a client gives you a device and has a build tree, ask
for `symbols/` and `module-info.json` before anything else.

---

### 32. Where is every platform permission defined?

`frameworks/base/core/res/AndroidManifest.xml`. It contains every platform permission with its exact
`protectionLevel`, including undocumented ones. It is faster and more accurate than the developer
documentation, and it is the file to cite when you need to say definitively whether a third-party app
can hold a given permission.

---

### 33. What is `system_server` and why does everything end up there?

A single process, forked from Zygote at boot, running as UID 1000, that hosts almost every framework
service: ActivityManager, PackageManager, WindowManager, PermissionManager, AppOps and dozens more. It is
the most privileged Java process on the device and the far side of nearly every Binder call an app makes.
Because the kernel stamps the caller's identity into each transaction, `system_server` is where
authorisation can be decided on an identity the caller cannot forge — which is why every enforcement
trace ends there.

`frameworks/base/services/java/com/android/server/SystemServer.java` lists every service and the order
they start in. Reading that file top to bottom is the fastest way to learn what exists.

---

### 34. Can I trace Binder traffic without patching AOSP?

Yes, in two ways. On a rooted device, the kernel's binder tracepoints give you transaction-level
visibility that no app can detect or disable:

```bash
adb shell 'echo 1 > /sys/kernel/debug/tracing/events/binder/enable'
adb shell cat /sys/kernel/debug/tracing/trace_pipe
```

And with Frida, one hook on `android.os.Binder.execTransact` sees every incoming Java Binder call in a
process, with the caller's UID and PID already available. Patching the platform is better when you have
the option, because it is below anything in user space, but these two cover most cases.

---

### 35. Is it legal and ethical to build and modify AOSP?

Building and modifying it is exactly what the licence permits and what it exists for. What requires care
is everything around it: redistributing GMS without a licence, testing a device you were not authorised
to test, and — most relevant here — reporting a finding you only reproduced on your own patched image.
A patched platform is a research instrument. Every finding must be reproduced on an unmodified image
before it goes in a report, and the report should say which image each piece of evidence came from.

---

### 36. AOSP is open source. Doesn't that make Android more secure?

Partly, and the honest answer is more interesting than either slogan. Openness genuinely buys:
independent audit of the core platform, a public and verifiable patch record, an ecosystem of analysis
tooling that closed platforms do not have, and — via GPL on the kernel — obligatory source for the layer
with the most severe bugs.

It does not buy: protection from the same diff being read by an attacker (that *is* patch gapping);
visibility into the closed components that implement the actual security controls (Play Integrity, Play
Protect, Play services); or any guarantee about the code on a specific device, since Apache 2.0 means the
OEM need publish nothing. The accurate statement is that openness improves the *verifiability of the
design* and the *velocity of research*, while the security of a particular device is mostly determined by
the vendor's code quality, patch cadence and configuration — none of which openness touches.

---

### 37. What are the highest-value greps in the whole tree?

Three, in order:

```bash
# 1. The confused deputy
rg -n -A25 "clearCallingIdentity" <tree>/services | grep -E "checkCalling|enforceCalling"

# 2. Every Binder service implementation — then check each for enforcement
rg -n "extends I[A-Za-z]+\.Stub\b" <tree> --glob '!*/test/*'

# 3. Weak custom permissions on preinstalled code
rg -n 'protectionLevel="normal"' vendor/ device/ packages/
```

All three work equally well on AOSP source and on a decompiled OEM framework, and on a vendor tree they
routinely produce findings within the first hour.

---

### 38. Where do I look for memory-safety bugs?

`external/` and `frameworks/av/`, because that is where large C/C++ parsers process untrusted input:
media containers and codecs, fonts, images, Bluetooth and NFC packet parsing, and the compression and
crypto libraries. The source being available is exactly what makes grammar-aware fuzzing and targeted
auditing practical there. On a specific device, also check which *versions* of those upstream projects
shipped, because OEMs routinely let them drift years behind.

---

### 39. How do I know which AOSP tag corresponds to a device's build?

`adb shell getprop ro.build.id` gives the build ID (for example `AP4A.241205.013`). Google publishes a
build-number table mapping build IDs to AOSP tags and Android versions (linked in
[references/README.md](references/README.md)). Match it, then set Code Search's branch selector to that
tag. Reading `main` while testing an older device is the single most common source of confusion in this
whole chapter.

---

### 40. This is a lot. What is the minimum I should take away?

Four things.

1. **The procedure**: name a symbol → find the implementation → follow the call → find `extends I*.Stub`
   → find `Binder.getCallingUid()`. Everything else in this chapter is an application of it.
2. **Identity is stamped by the kernel, once**, in `binder_transaction()`. In-process framework code is
   not a boundary, which is why client-side permission hooks grant nothing.
3. **Set the Code Search branch to match the device**, and record the fingerprint and both patch levels
   in your evidence.
4. **`service list` diffed against a stock image** enumerates an OEM's added attack surface in two
   minutes, and it is the thing people skip.
