# 63 — LSPosed · Cheat Sheet

Dense. Tables and commands. Prose lives in [README.md](README.md).

---

## The four layers

| Layer | Examples | What it does |
|---|---|---|
| Root | Magisk, KernelSU, APatch | Privilege |
| Injection | **Zygisk**, Riru | Gets a native library into Zygote |
| Framework | **LSPosed**, EdXposed, Xposed | Decides whose code runs where; installs hooks |
| Engine | **LSPlant**, YAHFA, SandHook, `hookMethodNative` | Rewrites the ART method |

## Framework comparison

| | Xposed (classic) | EdXposed | LSPosed |
|---|---|---|---|
| Injection | Replaces `/system/bin/app_process` | Riru module | **Zygisk module** |
| Engine | `hookMethodNative` | YAHFA / SandHook | **LSPlant** |
| Scope | Global — every process | Per-app (late) | **Per-app, per-process** |
| System partition | **Modified** | Untouched | **Untouched** |
| Max Android | 8.1 / API 27 | — | API 27 → 35+ |
| API | `de.robv.android.xposed` | same | same, plus `libxposed` |

---

## Module anatomy

| Requirement | Where |
|---|---|
| `xposedmodule` = `true` | `<application>` meta-data — **without it the manager will not list the APK** |
| `xposedminversion` = `82` | meta-data. An **Xposed API** number, not an Android or LSPosed version |
| `xposeddescription` | meta-data, one line |
| `xposedscope` = `pkg,pkg` | meta-data. A pre-selection **hint**, not enforcement |
| Entry class list | `assets/xposed_init`, one FQCN per line |
| Newer form | `META-INF/xposed/{module.prop,java_init.list,scope.list}` |
| API dependency | `compileOnly 'de.robv.android.xposed:api:82'` — **never `implementation`** |
| Keep rule | `-keep class * implements de.robv.android.xposed.IXposedMod { *; }` |

## Entry points

| Interface | Method | Where it runs | You have | You do not have |
|---|---|---|---|---|
| `IXposedHookZygoteInit` | `initZygote(StartupParam)` | Zygote, once | root, framework classes, `modulePath` | app classes, `Context`, package identity |
| `IXposedHookLoadPackage` | `handleLoadPackage(LoadPackageParam)` | app process, once per **process** | `classLoader`, `packageName`, `processName`, `appInfo` | `Context`, the `Application` object |
| `IXposedHookInitPackageResources` | `handleInitPackageResources(...)` | on resource load | `XResources` | anything computed at runtime |

## `LoadPackageParam`

| Field | Trap |
|---|---|
| `packageName` | Not unique per process |
| `processName` | Differs for `android:process` components. Wrong process = hook installs, never fires |
| `classLoader` | **Pass this for app classes.** `null` means the boot loader |
| `appInfo` | `sourceDir`, `dataDir`, `uid`, `FLAG_DEBUGGABLE` |
| `isFirstApplication` | False in a process hosting a second package |

---

## Installing hooks

```java
XposedHelpers.findAndHookMethod(String cls, ClassLoader cl, String m, Object... typesAndCallback);
XposedHelpers.findAndHookMethod(Class<?> c, String m, Object... typesAndCallback);
XposedHelpers.findAndHookConstructor(Class<?> c, Object... typesAndCallback);
XposedBridge.hookAllMethods(Class<?> c, String name, XC_MethodHook cb);      // Set<Unhook>
XposedBridge.hookAllConstructors(Class<?> c, XC_MethodHook cb);              // Set<Unhook>
XposedBridge.hookMethod(Member m, XC_MethodHook cb);                         // Unhook
XposedBridge.invokeOriginalMethod(Member m, Object self, Object[] args);     // unhooked call
```

**The callback must be the LAST varargs element.** Types may be `Class` objects or FQCN strings.

## `XC_MethodHook` semantics

| Operation | In `beforeHookedMethod` | In `afterHookedMethod` |
|---|---|---|
| `param.args[i] = v` | Changes what the original receives | No effect |
| `param.setResult(v)` | **Skips the original body** | Rewrites the caller's value |
| `param.setThrowable(t)` | Skips the original; the call throws | The call throws |
| `param.getResult()` | `null` | The value about to be returned |
| `param.hasThrowable()` | `false` | True if the original threw |
| `param.thisObject` | Receiver, `null` if static | Same |
| `param.method` | The hooked `Member` | Same |

`afterHookedMethod` runs **even when `before` skipped the original.**
`setResult` clears the throwable; `setThrowable` clears the result.

## Priority

```
HIGHEST.before -> DEFAULT.before -> LOWEST.before -> ORIGINAL -> LOWEST.after -> DEFAULT.after -> HIGHEST.after
```

`PRIORITY_DEFAULT = 50`, `PRIORITY_LOWEST = -10000`, `PRIORITY_HIGHEST = 10000`.
A high-priority `setResult` in `before` **silently prevents every lower hook from running.**

## `XposedHelpers`

| Call | Replaces |
|---|---|
| `findClass(name, cl)` / `findClassIfExists` | `Class.forName(name, false, cl)` |
| `getObjectField` / `getIntField` / `getBooleanField` / `getLongField` | `getDeclaredField` + `setAccessible` + `get` |
| `setObjectField` / `setIntField` / `setBooleanField` | the same, writing |
| `getStaticObjectField` / `setStaticObjectField` | the same, on a `Class` |
| `callMethod` / `callStaticMethod` | `getDeclaredMethod` + `invoke` |
| `newInstance` | `getDeclaredConstructor().newInstance()` |
| `get/setAdditionalInstanceField` | *nothing* — a weak-keyed per-object side table |

**Access modifiers are ignored entirely. `private` is a compiler concept.**

---

## Timing

```
Zygote start -> initZygote -> fork -> specialize(uid,SELinux,seccomp) -> handleLoadPackage
  -> Application.attachBaseContext -> ContentProvider.onCreate -> Application.onCreate -> Activity.onCreate
```

Need a `Context`? Hook `android.app.Application.attachBaseContext(Context)` and use `args[0]`.

---

## Scope

| Entry | Meaning | Risk |
|---|---|---|
| An ordinary package | Loads into that app, at that app's uid | Bounded by the app's sandbox |
| **`android`** | Loads into **`system_server`**, uid 1000, platform permissions | **Critical.** Unrestricted code in the platform process |

---

## Limits — what a module cannot do

| Cannot | Use instead |
|---|---|
| Hook a native function | Frida, or your own engine loaded from the module |
| Reach an inlined method | `cmd package compile -m verify -f`, or hook the caller |
| Trace / coverage / `Stalker` | Frida |
| Change anything without a restart | Frida |
| Run unrooted | Frida gadget; JDWP on a debuggable app |
| Reach a DenyListed process | Take it off the DenyList |
| Run in `android:isolatedProcess` | Hook the other side of the IPC |
| Get root | Zygisk companion |

---

## Diagnostic order when a hook does not fire

| # | Check | Command |
|---|---|---|
| 1 | Process restarted? | `adb shell am force-stop <pkg>` |
| 2 | Enabled **and scoped**? | LSPosed manager |
| 3 | On the DenyList? | `adb shell 'su 0 magisk --denylist ls'` |
| 4 | Module loaded at all? | LSPosed log |
| 5 | `handleLoadPackage` entered? | Log unconditionally on line 1 |
| 6 | Right process? | Log `lpparam.processName` |
| 7 | Install threw? | Your `catch` must log it |
| 8 | Inlined? | `adb shell cmd package compile -m verify -f <pkg>`, force-stop, retry |
| 9 | Foreign class loader? | Hook `ClassLoader.loadClass` |
| 10 | Anything calls it? | jadx; look for the call site |

---

## Device commands

```bash
# posture, all of the below in one run
./scripts/lsposed-footprint.sh --serial <serial> --as-package <debuggable-pkg>

# root — TRY BOTH.  The AVD takes `su 0`; phones take `su -c`.
adb shell 'su 0 id'
adb shell 'su -c id'

# Magisk
adb shell 'su 0 /debug_ramdisk/magisk -v'         # 30.7:MAGISK:R  on the reference AVD
adb shell 'su 0 /debug_ramdisk/magisk -V'         # 30700
adb shell 'su 0 /debug_ramdisk/magisk --list'
adb shell 'su 0 /debug_ramdisk/magisk --denylist ls'

# Zygisk — TWO independent checks; an absent settings row means DEFAULT, not OFF
adb shell 'su 0 /debug_ramdisk/magisk --sqlite "select * from settings"'
adb shell 'su 0 sh -c "grep -icE \"zygisk\" /proc/$(pidof zygote64)/maps"'

# modules
adb shell 'su 0 sh -c "ls -d /data/adb/modules/*/ ; cat /data/adb/modules/*/module.prop"'

# lspd in system_server
adb shell 'su 0 sh -c "grep -icE \"lspd|lsposed|xposed\" /proc/$(pidof system_server)/maps"'

# a module loaded into a live app
adb shell 'su 0 ls -la /proc/$(pidof <pkg>)/fd' | grep -i apk

# the substrate, from ANY uid, no permissions needed
adb shell 'grep -E "magisk|zygisk" /proc/self/mountinfo'
```

---

## Static triage of a module APK

```bash
python3 -B scripts/detect-xposed-module.py module.apk --verbose

unzip -l module.apk | grep -iE 'assets/xposed_init|META-INF/xposed'
unzip -p module.apk assets/xposed_init                       # entry class, plaintext, always
unzip -p module.apk AndroidManifest.xml | strings | grep -i xposed
unzip -o module.apk classes.dex -d out
dexdump -d out/classes.dex | grep -oE 'Lde/robv/android/xposed/[A-Za-z0-9$/_]+;' | sort -u
strings out/classes.dex | grep -E '^[a-z][a-z0-9_]*(\.[a-zA-Z][A-Za-z0-9_]*){2,}$' | sort -u
unzip -l module.apk | grep de/robv                           # MUST be empty (compileOnly)
```

---

## Detection — what works and what does not

| Check | Verdict |
|---|---|
| `pm.getPackageInfo("org.lsposed.manager")` | **Broken.** Often not an installed launcher app; name randomisable; API 30 package visibility breaks the query anyway |
| `new File("/data/adb/lspd").exists()` | **Broken and measurable.** Returns `false` whether or not LSPosed is installed: `/data/adb` is `EACCES` to every app, and `File.exists()` maps `EACCES` and `ENOENT` alike to `false` |
| `/system/framework/XposedBridge.jar` | **Broken.** A *classic Xposed* artefact. LSPosed never creates it |
| `Class.forName("de.robv.android.xposed.XposedBridge")` | **Works** — proves the framework is in *this* process. Defeated by hooking `ClassLoader.loadClass` |
| Foreign class loaders in our graph | **Works.** Defeated by hooking `ClassLoader.getParent` |
| Dispatcher frame in `new Throwable().getStackTrace()` | **Works.** Defeated by hooking `getStackTrace` |
| Entry point outside boot image / `.odex` / JIT cache | **Works, strongest.** Needs native code |
| `/proc/self/mountinfo` naming `magisk` | Proves the **root substrate**, not LSPosed. Readable by any app, no permissions |
| Server-verified hardware attestation | **The only one that changes the outcome rather than the cost** |

---

## Measured reference figures

| Fact | Value | Where |
|---|---|---|
| Reference device | AVD `sdk_gphone16k_x86_64`, Android 15 / API 35, x86_64 | §7.1 |
| Root | Magisk **30.7** (`30700`), binary at `/debug_ramdisk/magisk` | §7.1 |
| `su` convention there | **`su 0 <cmd>`** — `su -c` fails with `invalid uid/gid '-c'` | §7.1 |
| Zygisk | **off** — no settings row, no mapping in `zygote64` | §7.1 |
| `/data/adb/modules` | **empty** | §7.1 |
| LSPosed | **not installed** — every LSPosed-specific claim is source-level | §7.1 |
| `/data/adb` from an app uid | `EACCES`; a non-existent sibling gives `ENOENT` | §3.17 |
| `/data/adb/lspd` | root: `ENOENT` · shell and app: `EACCES` | §3.17 |
| `/debug_ramdisk` | mode `0711` — stat-able, **not** listable | §3.17 |
| `/debug_ramdisk/magisk` | **readable from an app uid** (ELF header dumped) | §3.17 |
| `/proc/self/mountinfo` | **3** lines matching `magisk` — **2** whose *source* is `magisk`, 1 a `devpts` whose *mount point* is `/debug_ramdisk/.magisk/pts` | §3.17 |
| `/sys/fs/selinux/policy` | DAC `0444`, **SELinux denies the read from an app** | §3.17 |
| Chapter's own module DEX | 13 sources → 27 classes → **9 dexed**, 11,272 bytes | §6 |
| `setResult` occurrences in it | **0** — a `static final boolean` eliminated the branch | §6.3 |

---

## Related chapters

| | |
|---|---|
| [13-ART](../13-ART/README.md) | Owns `ArtMethod` and the entry point |
| [62-Magisk](../62-Magisk/README.md) | Owns root, modules and **Zygisk** |
| [65-Hooking](../65-Hooking/README.md) | Owns hooking mechanism; LSPosed is its type 1 |
| [53-Frida](../53-Frida/README.md) | Owns Frida; §7.9 extends its comparison |
| [64-Xposed](../64-Xposed/README.md) | The historical framework |
| [67-BypassingProtections](../67-BypassingProtections/README.md) | Owns the detection arms race |
