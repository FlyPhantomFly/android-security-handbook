# 63 — LSPosed · FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct; the reasoning
is in [README.md](README.md).

---

**1. I keep seeing "Xposed", "EdXposed" and "LSPosed". Are they the same thing?**

No, and this is the single most common confusion. Think of four independent layers:

- **Root** — Magisk, KernelSU, APatch. Gives privilege.
- **Injection** — Zygisk, Riru. Gets a native library into Zygote.
- **Framework** — Xposed, EdXposed, LSPosed. Decides whose code runs where.
- **Engine** — `hookMethodNative`, YAHFA, SandHook, LSPlant. Actually rewrites the method.

Classic **Xposed** (rovo89) replaced `/system/bin/app_process` and stopped at Android 8.1.
**EdXposed** used Riru injection with YAHFA or SandHook. **LSPosed** uses Zygisk injection with
LSPlant, and is current. All three implement the same **API**, `de.robv.android.xposed`, which is why
a module from 2015 still loads today.

---

**2. Does a module run as root?**

No. This is the most common wrong answer in interviews. A module runs **as the target application**,
with its uid, its permissions and its SELinux domain. The framework was root — in Zygote, before the
`fork()` — and the child gave that up during specialisation, milliseconds before your code ran.

If a module needs privilege it has to ask something privileged. That is what Zygisk's
`connectCompanion()` is for, and it is why LSPosed keeps a daemon rather than doing everything
in-process.

---

**3. Why does LSPosed need Magisk? Can I use it on an unrooted phone?**

No. LSPosed is implemented as a Zygisk module, and Zygisk is Magisk's mechanism for loading a library
into Zygote. No root, no library in Zygote, no framework. There is no unrooted variant and there
cannot be a straightforward one, because getting code into Zygote requires privilege by construction.

On an unrooted device your options are a Frida gadget in a repackaged APK, or JDWP against a build
with `android:debuggable="true"`. See [53-Frida](../53-Frida/README.md).

---

**4. What actually makes an APK a "module"? Is it a special file format?**

No, it is an ordinary APK with three additions:

1. `<meta-data android:name="xposedmodule" android:value="true"/>` in the manifest.
2. `assets/xposed_init` — a text file naming your entry class or classes.
3. A compile-time-only dependency on the Xposed API.

That is all. See [`examples/AndroidManifest.xml`](examples/AndroidManifest.xml) and
[`examples/xposed_init`](examples/xposed_init).

---

**5. Why must the API be `compileOnly` and not `implementation`?**

Because the framework supplies `de.robv.android.xposed.*` inside the target process at runtime. If
your APK packages its own copy, your code calls **your** `XposedBridge` — a different class, loaded
by a different loader, from the one LSPosed loaded — and every hook you install goes into an object
nobody consults.

The symptom is horrible: the module loads cleanly, throws nothing, logs nothing and hooks nothing.
Check with `unzip -l module.apk | grep de/robv` — it must return **nothing**.

---

**6. My hook installs and never fires. What is wrong?**

Work through this in order; each step is cheap and rules out a whole class of cause.

1. **Did the process restart?** A module is loaded at process *start*. `adb shell am force-stop <pkg>`.
2. Is the module **enabled and scoped** to this package?
3. Is the target on Magisk's **DenyList**? LSPosed skips DenyListed processes.
4. Did `handleLoadPackage` run at all? Log unconditionally on its first line.
5. Are you in the right **process**? Log `lpparam.processName` — an `android:process` component gets
   its own.
6. Did `findAndHookMethod` **throw**? Your `catch` must log it.
7. Was the method **inlined**? `adb shell cmd package compile -m verify -f <pkg>`, force-stop, retry.
8. Is the class loaded by a loader you cannot see? Hook `ClassLoader.loadClass`.

Steps 4 and 6 are the ones people skip, and skipping them is how an afternoon disappears. "Never
entered" and "entered but the installation threw" are different problems.

---

**7. Why does `findAndHookMethod` need a `ClassLoader`? Can I just pass `null`?**

Only for framework classes. A class *name* is meaningless without a loader — the boot loader knows
`android.app.Activity` and has never heard of `com.example.Gate`. Your module's own loader has not
either. Only `lpparam.classLoader` has.

Passing `null` for an application class gives you `ClassNotFoundError`, every single time.

---

**8. I can see the class in jadx, but the module says `ClassNotFoundError`. How?**

The class is in the APK; it is not in the loader you asked at the time you asked. Something loads it
later with its own loader — a plugin architecture, a dynamic feature module, or a packer that
decrypts the real DEX at runtime.

Stop trying to resolve it. Hook `ClassLoader.loadClass` and install your real hooks the moment the
class appears. [`examples/LateClassHookModule.java`](examples/LateClassHookModule.java) is the full
pattern, including the one-shot guard you will otherwise forget.

---

**9. What is the difference between `setResult` in `before` and in `after`?**

In `beforeHookedMethod`, `setResult` **skips the original method body entirely**. In
`afterHookedMethod` the original has already run and `setResult` only changes what the caller sees.

The consequence people get bitten by: a method that returns a boolean *and* increments a counter,
short-circuited from `before`, stops incrementing the counter. If the app later checks the counter,
your bypass has changed something you did not intend.

`afterHookedMethod` runs either way, including after a `before` that skipped the original.

---

**10. Two modules hook the same method. What happens?**

They nest by `priority`. The higher-priority hook's `before` runs **first** and its `after` runs
**last** — it wraps the others like an onion skin.

The sharp edge: a high-priority hook that calls `setResult` in `before` prevents the original body
*and* every lower-priority hook's `before` from running at all, and nothing logs anything about it.
If your module's correctness depends on running before somebody else's, set a priority and say so in
the module's description.

---

**11. Can a module hook native code?**

Not through the Xposed API. Its only primitive is replacing an ART method's entry point — chapter
[65-Hooking](../65-Hooking/README.md)'s hook type 1. You can hook the Java `native` declaration and
see its arguments and return value; you cannot see inside it.

Nothing stops you loading your own `.so` from a module once you are inside the process and doing
native inline hooking from there — but that is you writing a hooking engine and calling it from a
module, not the API doing it for you. If the decisions you care about are behind `native`
declarations, use Frida.

---

**12. LSPosed or Frida?**

**Explore with Frida; ship with LSPosed.**

Frida wins on the feedback loop, which is what you need while you are still wrong about the
signature, the class loader and which layer the call uses. Reach for LSPosed when:

- the target dies or behaves differently when `ptrace`d;
- you need to be inside a `static {}` block or `ContentProvider.onCreate`;
- the observation has to survive reboots and run for days;
- you need `system_server` instrumented continuously;
- you have to hand the capability to somebody who is not you — a module is an APK.

Almost every module worth having started life as a Frida script.

---

**13. What does "scope" mean, and why does everyone say to be careful with it?**

Scope is a per-module list of packages. The module's DEX is loaded only into processes belonging to
those packages. It is LSPosed's biggest improvement over classic Xposed, which ran every module in
every process.

The care is about one entry. Alongside ordinary packages, the list contains **`android`** — the
system framework. Ticking it loads the module into **`system_server`**, at uid 1000, with the
platform's permissions. A hook there sees every Binder transaction on the device: every activity
launch, every notification, every permission check.

The manager's checkbox for `android` looks exactly like the checkbox for a notes app. It is not the
same thing. Treat enabling it as installing a system app you did not build.

---

**14. Is LSPosed detectable?**

Yes, from inside the process, and no, from the artefacts most detectors look for.

**What does not work** — and this is measured, not asserted:

- `pm.getPackageInfo("org.lsposed.manager")`: LSPosed's manager is frequently not an installed
  launcher app at all, its package name can be randomised, and API 30 package-visibility rules break
  the query independently.
- `new File("/data/adb/lspd").exists()`: on the reference device, root reports that path genuinely
  `ENOENT` — LSPosed is not installed — while both `shell` and an app uid get `EACCES`, because the
  refusal happens at `/data/adb`. `File.exists()` maps both to `false`. **The check returns the same
  answer whether or not LSPosed is installed.**
- `/system/framework/XposedBridge.jar`: a *classic Xposed* artefact. LSPosed never creates it.

**What does work**, from inside the app: is `de.robv.android.xposed.XposedBridge` resolvable in this
process; is there a foreign class loader in our graph; is there a dispatcher frame on our own stack;
does a method's entry point fall outside the boot image, the app's `.odex` and the JIT cache.

All four are defeatable by a module that hooks the thing doing the checking — because the checker and
the checked share an address space. The only control that changes the outcome rather than the cost is
server-verified hardware attestation.

---

**15. If I install LSPosed but scope a module to nothing, is my banking app being hooked?**

No. That is the distinction most detection write-ups miss. "Is LSPosed installed on the device?" and
"is *this app* being hooked?" are different questions with different answers. An application outside
every module's scope loads no foreign DEX, has no foreign class loader, and has no framework classes
resolvable in its process.

The framework is installed; it has done nothing to that app.

---

**16. Does LSPosed modify my apps or the system partition?**

Neither. No file on disk changes. The APKs in `/data/app` are byte-identical to the ones that were
installed and their signatures still verify. `/system/bin/app_process` is the stock binary.

You can demonstrate it, and it is worth putting in a report next to a finding:

```bash
adb shell 'su 0 sha256sum /data/app/~~*/<pkg>-*/base.apk'
adb shell 'dumpsys package <pkg> | grep -A2 signatures'
```

Both come back clean on a hooked app. That is why [38-TamperDetection](../38-TamperDetection/README.md)
classifies runtime instrumentation as leaving **nothing** on disk, and why an integrity check over
the APK cannot see it.

---

**17. I changed my module, reinstalled it, and nothing happened. Why?**

Force-stop the target. `adb shell am force-stop <pkg>`.

A module is loaded when the target process starts. Reinstalling the module APK, enabling it, or
changing its scope has no effect on a process that is already running — and Android keeps app
processes alive for a long time after you leave the app. This is the single most common "LSPosed is
broken" report and it is not broken.

Some changes — enabling the framework itself, or a scope change involving `android` — additionally
need a reboot.

---

**18. Can I use LSPosed and Frida at the same time?**

Yes, and one combination is genuinely useful: a minimal module whose only job is to run at
`handleLoadPackage` and hold the process still — for instance by blocking in a hook until a file
appears — after which you attach Frida and do the real work. You get the module's timing with Frida's
feedback loop.

The cost is two instruments in one process, either of which can confuse the other. If a result
surprises you, remove one and re-check.

---

**19. Why is the manager sometimes not in my app drawer?**

By design. LSPosed's manager is commonly launched *through* the system rather than as an ordinary
installed application, which removes one artefact a detector could look for. Depending on the build
it is reachable through a shortcut, a dial-pad code, or the Magisk app.

The practical consequence: **"no LSPosed icon" is not evidence of absence**, and neither is
`pm list packages | grep lsposed`.

---

**20. What is a "backup method" and why does the API never mention it?**

Because it is an implementation detail you never touch — and it is the most interesting one.

`XC_MethodHook` promises that the original body runs between `before` and `after`. But the original's
entry point has just been overwritten by your hook, so something must keep a second way in. The
engine creates a synthetic `ArtMethod` — the backup — carrying the entry pointer the target had
before the hook. The dispatcher calls it between the two callbacks.

It is the managed-layer twin of an inline hook's trampoline in
[65-Hooking](../65-Hooking/README.md): if you want to call through, you must keep a copy of what you
destroyed. Different layer, different artefact, same reason.

---

**21. Is it safe to install a module I found on a forum?**

Treat it exactly as you would treat installing an unsigned system app. A module runs inside other
applications with their identity, and if it is scoped to `android` it runs in the platform process.
Build from source you have read, or do not enable it — and never on a device that holds real
credentials.

Triage one before you install it:

```bash
python3 -B scripts/detect-xposed-module.py module.apk --verbose
```

And note the limit that script prints for you: **absence of `setResult` in the DEX proves very
little.** This chapter measured its own module — a `static final boolean` guard caused `javac` to
eliminate the entire behaviour-changing branch, so the capability is absent from the bytecode and one
character away in the source. When the question is trust, the artefact to review is the source and
the build.

---

**22. Why is `su -c id` failing on my emulator? Is it not rooted?**

Probably it is. The AOSP emulator's `su` takes a **uid as its first argument**:

```
$ adb shell 'su -c id'
su: invalid uid/gid '-c'          # reads as "not rooted", is not

$ adb shell 'su 0 id'
uid=0(root) gid=0(root) ... context=u:r:su:s0
```

Physical devices with Magisk take the `-c` form. **Try both before recording a device as unrooted** —
a chapter in this repository nearly made exactly that mistake.

---

**23. `initZygote` or `handleLoadPackage` — which do I use?**

`handleLoadPackage`, almost always.

Use `initZygote` only for hooks on **framework** classes that must be in place before the first
application starts, and for reading your own module's assets while you still have root. You have no
application classes there, no `Context`, and no package identity — the process is Zygote and no app
exists yet.

If you need a `Context`, neither entry point gives you one: hook
`android.app.Application.attachBaseContext(Context)` from `handleLoadPackage` and take `args[0]`.

---

**24. My module needs settings. Where do I put them?**

This is genuinely awkward, and the awkwardness is structural. Your settings Activity runs in the
**module's** process; your hooks run in the **target's** process; the two share nothing.

Historically the answer was world-readable `SharedPreferences`, which Android 7 removed. Modern
options: LSPosed's remote-preferences bridge, a `ContentProvider` in your module that the hook side
queries, or — simplest and what this chapter's examples do — ship configuration inside the module APK
so that changing it means rebuilding.

One warning if you register a receiver inside the target to drive your module (chapter §9.4 does):
a dynamically-registered receiver with no permission is **exported**, so any app on the device can
drive it. Pass a `broadcastPermission`, or use `RECEIVER_NOT_EXPORTED` on API 33+. Your module's own
code is attack surface inside somebody else's process.

---

**25. What should I put in a report when a module bypassed a control?**

Not "the app can be hooked". That is a property of the platform on a rooted device, not a
vulnerability, and reporting it as one is the fastest way to lose a developer's attention.

Report what the hook **proved**, and rate the *server-side* consequence:

- If the module read a hard-coded PIN, the finding is the PIN — and demonstrate it working on a clean
  device with no module installed. A finding that only reproduces under instrumentation is weaker
  than one that does not.
- If the module flipped a boolean that gates a server-side action the server grants on the client's
  word, the finding is the **unprotected server-side action**, and that can be High.
- If it flipped a boolean that gates only a client-side UI, the finding is Informational.

And record the methodology: which device, which root implementation, which modules were enabled with
what scope, and that you removed them. A module left behind on a client device is a finding against
you.
