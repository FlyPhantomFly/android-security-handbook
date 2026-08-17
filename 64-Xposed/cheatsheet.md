# 64 — Xposed · Cheat Sheet

Dense reference. Prose lives in [README.md](README.md).

**⚠ Two-tier marking.** Rows marked **[M]** are measured on `sdk_gphone16k_x86_64`, Android 15 /
API 35, Magisk 30.7 — see README §7.1. Rows marked **[D]** are documentation-derived from the
framework's published design and the AOSP it modified; classic Xposed was **not installed anywhere**
and no session with it was fabricated.

---

## The one-paragraph summary

Classic Xposed replaced `/system/bin/app_process` so its jar sat on the **boot class path** of every
process; `hookMethodNative` set `kAccNative` on a target `ArtMethod`, pointed `data_` at a single
dispatcher, and kept a struct copy as the backup. It had **no scope**. Support ended at **API 27**.
The **API survived** and [63-LSPosed](../63-LSPosed/README.md) implements it. The **detection surface
survived too**, and is dead code in shipping applications.

---

## Timeline

| Era | Name | Injection | Engine | Scope |
|---|---|---|---|---|
| 2012–14 | Xposed (Dalvik) | Replaced `app_process` | `libxposed_dalvik.so`, `nativeFunc` | none |
| 2014–18 | Xposed (ART) | Replaced `app_process` | `libxposed_art.so`, `hookMethodNative` | none |
| 2018–21 | EdXposed | **Riru** module | YAHFA or SandHook | per-app (late) |
| 2019– | VirtualXposed / TaiChi | container / repackage | varies | n/a |
| 2021– | **LSPosed** | **Zygisk** module | **LSPlant** | per-app, per-process |

**The break is at the injection layer, not the hooking layer.**

---

## Version matrix

| Fact | Value |
|---|---|
| Xposed for Dalvik | API 15–19 |
| Xposed for ART | API 21–27 |
| **Official support ends** | **Android 8.1 / API 27** |
| dm-verity available / Verified Boot mandatory | 4.4 / 7.0 |
| A/B seamless updates | 7.0 |
| Project Treble | 8.0 |
| **ART becomes a Mainline module** | **API 29** |
| Zygisk available | Magisk 24+ |
| LSPosed range | API 27–35 |
| **Xposed API version** | **82** — not an Android version, not an LSPosed version |

---

## What a classic install wrote [D, probed [M]]

| Path | Purpose |
|---|---|
| `/system/bin/app_process*` | **Replaced.** The framework's own build |
| `/system/bin/app_process.orig` | The saved stock binary — the real signature |
| `/system/framework/XposedBridge.jar` | On the **boot class path** |
| `/system/lib64/libxposed_art.so` | ART engine |
| `/system/lib/libxposed_art.so` | 32-bit build |
| `/system/lib/libxposed_dalvik.so` | Dalvik engine |
| `/system/xposed.prop` | Version, arch, minsdk, maxsdk. Also a kill switch |
| `/data/data/de.robv.android.xposed.installer` | The installer |
| `/data/xposed/` | Staging |

Systemless equivalent: **zero files.** See [62-Magisk](../62-Magisk/README.md).

---

## Three-vantage artefact table [M]

| Path | root | shell | app |
|---|---|---|---|
| `/system/framework/XposedBridge.jar` | `ENOENT` | `ENOENT` | `ENOENT` |
| `/system/xposed.prop` | `ENOENT` | `ENOENT` | `ENOENT` |
| `/system/lib64/libxposed_art.so` | `ENOENT` | `ENOENT` | `ENOENT` |
| `/system/bin/app_process` | PRESENT | PRESENT | PRESENT |
| `/system/bin/app_process32` | `ENOENT` | `ENOENT` | `ENOENT` |
| `/system/bin/app_process64` | PRESENT | PRESENT | PRESENT |
| `/system/bin/app_process.orig` | `ENOENT` | `ENOENT` | `ENOENT` |
| `/data/data/de.robv…installer` | `ENOENT` | `ENOENT` | `ENOENT` |
| `/data/adb/modules` | **PRESENT** | `EACCES` | `EACCES` |
| `/data/adb/lspd` | `ENOENT` | `EACCES` | `EACCES` |

```
lrwxr-xr-x root shell    13  /system/bin/app_process -> app_process64
-rwxr-xr-x root shell 51616  /system/bin/app_process64
/dev/block/dm-5 / ext4 ro,seclabel,relatime
ro.boot.veritymode = enforcing        ro.boot.verifiedbootstate = <EMPTY>
```

**`File.exists()` returns `false` for both `ENOENT` and `EACCES`.** Classic paths: absent. `/data/adb`
paths: forbidden. Same output, opposite causes, only one could ever change.

---

## `hookMethodNative` [D]

| # | Operation | Field | Why |
|---|---|---|---|
| 1 | `memcpy` the `ArtMethod` | all | **The backup** — reaches the original body |
| 2 | Set `kAccNative` | `access_flags_` | Runtime stops looking for bytecode |
| 3 | Entry → generic JNI trampoline; `data_` → dispatcher | `entry_point_…`, `data_` | Where dispatch lands |
| 4 | Set `kAccCompileDontBother` | `access_flags_` | Or the JIT overwrites the entry point |

Dalvik form: set the native flag, write `Method.nativeFunc`, keep a copy.
Structure owned by [13-ART §3.15–3.17](../13-ART/README.md). Hook type 1 in
[65-Hooking §3.3](../65-Hooking/README.md).

**Runtime signature unique to classic Xposed:** a method **with bytecode** whose flags claim
`kAccNative`. Not a state ART produces. LSPlant does not create it.

---

## Dispatcher control flow [D] — and why the API is shaped this way

```
identify method -> sorted callback list -> build MethodHookParam
  for each cb, HIGHEST first:  beforeHookedMethod
  unless setResult/setThrowable was called:  invoke the SAVED ArtMethod
  for each cb, LOWEST first:   afterHookedMethod
  return getResultOrThrowable()
```

| API behaviour | Caused by |
|---|---|
| `setResult` in `before` skips the original | the condition on the invoke |
| `after` runs even when the original was skipped | it is unconditional |
| `args[i] = v` works in `before`, not in `after` | the array is passed to the invoke |
| Higher priority **wraps** lower | the two loops iterate in opposite orders |

Classic stack frame: `de.robv.android.xposed.XposedBridge.handleHookedMethod`
LSPosed's instead: a generated class containing **`LSPHooker`**

---

## Module format

| Element | Required | Note |
|---|---|---|
| `xposedmodule` meta-data | **Yes** | Value `true`. The load-bearing declaration |
| `xposedminversion` meta-data | In practice | **`82`** |
| `xposeddescription` meta-data | Recommended | One line |
| `xposedscope` meta-data | Recommended | Docs under classic; **pre-selects scope** under LSPosed |
| `assets/xposed_init` | **Yes** | One FQCN per line. **Plaintext, always** |
| API dependency | **`compileOnly`** | **Never `implementation`** |

**`compileOnly` failure:** the module's code calls its *own* `XposedBridge`. Loads cleanly, logs
nothing, hooks nothing, **no error at any stage.**

Verify: `unzip -l module.apk | grep de/robv` must be **empty**.

---

## Measured module build [M]

```
21 class files compiled -> 4 dexed (17 API classes excluded, as compileOnly would)
classes.dex: 10940 bytes
10 distinct de.robv types REFERENCED, 0 DEFINED
```

```
Lde/robv/android/xposed/IXposedHookLoadPackage;
Lde/robv/android/xposed/IXposedHookZygoteInit$StartupParam;
Lde/robv/android/xposed/IXposedHookZygoteInit;
Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;
Lde/robv/android/xposed/XC_MethodHook$Unhook;
Lde/robv/android/xposed/XC_MethodHook;
Lde/robv/android/xposed/XC_MethodReplacement;
Lde/robv/android/xposed/XposedBridge;
Lde/robv/android/xposed/XposedHelpers;
Lde/robv/android/xposed/callbacks/XC_LoadPackage$LoadPackageParam;
```

**A dangling `de.robv` reference IS the module format.**

---

## Corpus sweep [M] — 237 APKs, stock Android 15 image

```
APKs readable            : 237
classes*.dex STORED      : 234
classes*.dex DEFLATED    :  16   <- all in /data/app; 10 of them Chrome's
reaching STRONG          :   1   <- the Magisk app naming a module. Not detection code
reaching MEDIUM          :  94
no signature at all      : 136

genuine Xposed-detection code: 0
```

### The two false-positive classes

| Class | Measurement |
|---|---|
| **`exposed` contains `xposed`** | 58/237 APKs match `grep -i xposed`. **1141 occurrences, 1141 explained, 0 unexplained.** 100% false |
| **R8 manufactures short tokens** | A 3-char probe (`vxp`) produced **16 STRONG hits**, all `Lvxp;`/`Lavxp;` minified class names. **Gets worse on better-protected apps** |

**Rule: never put a token under ~8 characters in a high-confidence tier.**

---

## Why it died — five forces, none aimed at it

| Force | Closed |
|---|---|
| Writable `/system` | dm-verity 4.4, mandatory Verified Boot 7.0 |
| Per-release `app_process` port | Treble 8.0 + annual cadence — **the decisive one** |
| Stable `ArtMethod` layout | **ART Mainline at API 29** — the version no longer determines the layout |
| Surviving OTA | A/B block-level updates |
| Any reason to keep it | Riru, then Zygisk: same result, no partition write |

---

## Detection checks, ranked

| Check | Verdict |
|---|---|
| `new File("/system/framework/XposedBridge.jar").exists()` | **[M] DEAD.** `ENOENT` to root |
| `libxposed_art.so`, `xposed.prop` | **[M] DEAD.** Same |
| `getPackageInfo("de.robv…installer")` | **[D] DEAD ×2.** Uninstallable since API 27; **and** API 30 package visibility breaks it without `<queries>` |
| `app_process` size/hash vs a constant | **[M] WORSE THAN DEAD.** No baseline exists; it is a symlink; false-positives clean devices |
| `Class.forName("de.robv…XposedBridge")` | **KEEP.** Meaning changed: device-wide under classic (boot class path), **this-process** under LSPosed |
| Stack frame `handleHookedMethod` | **KEEP, and add `LSPHooker`** |
| `kAccNative` on a method with bytecode | **STRONGEST.** Classic-specific, needs no baseline |
| Send signals + attested token to a server | **The only one that changes the outcome** |

---

## Commands

```bash
# posture, always first
adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk
adb shell 'su 0 id' || adb shell "su -c 'id'"        # TRY BOTH

# three-vantage artefact table
./scripts/xposed-artefact-probe.sh --serial <s> --as-package <debuggable pkg>

# corpus
./scripts/pull-apk-corpus.sh --serial <s> --third-party-only --out /tmp/apks
python3 -B scripts/xposed-detection-scan.py /tmp/apks --recursive --substring-audit
python3 -B scripts/xposed-detection-scan.py /tmp/apks --recursive --min-tier 1 --verbose

# build a classic-API module offline
./scripts/build-classic-module.sh --with-detector --disassemble --keep

# module triage, by hand
unzip -p module.apk assets/xposed_init                       # entry class, plaintext, always
unzip -l module.apk | grep -i 'assets/xposed\|META-INF/xposed'
unzip -l module.apk | grep de/robv                            # must be EMPTY (compileOnly)

# DEX strings, portably (NOT `strings` on Windows -- Sysinternals build, CRLF, MSYS paths)
python3 -B -c "import re,sys;d=open(sys.argv[1],'rb').read();[print(m.decode()) for m in sorted(set(re.findall(rb'Lde/robv/android/xposed/[A-Za-z0-9\$/_]+;',d)))]" classes.dex

# is the mechanism even possible here?
adb shell 'cat /proc/self/mounts' | grep -E ' / | /system '
adb shell getprop ro.boot.veritymode
adb shell 'ls -l /system/bin/app_process*'

# hook installed but never fires
adb shell cmd package compile -m verify -f <pkg> && adb shell am force-stop <pkg>
```

---

## Gotchas

| Trap | Correct form |
|---|---|
| `su -c` on an emulator | **`su 0 <cmd>`** |
| `adb shell su -c 'cmd'` | **`adb shell "su -c 'cmd'"`** — the outer shell strips quotes and `su` eats the flag | <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- trap table: the first cell IS the wrong form, the second is the fix -->
| `grep -i xposed` | 100% false positives. Anchor on `de.robv`, `/system/framework/XposedBridge.jar`, etc. |
| Device-side grep over `.apk` | Blind to deflated DEX — **all of them in `/data/app`** |
| `strings` on Windows | Sysinternals build: MSYS paths fail, CRLF breaks anchored greps. Use Python |
| `javac` `@argfile` with spaces | **Quote each path.** `invalid flag: C:/Users/.../Android` |
| `d8` `@argfile` | **Does NOT strip quotes.** `InvalidPathException: Illegal char <">`. Pass a jar |
| `adb shell` inside `while read` | It eats stdin. Add `< /dev/null` |
| `set -o pipefail` + `head`/`grep -q` | SIGPIPE → spurious failure. Test content, not exit status |
| jadx on a bare `classes.dex` | jadx 1.5.3 produces no output, exits 0, hangs on `.jar`. Use baksmali |
| Module changed, nothing happened | `adb shell am force-stop <pkg>` — modules load at process start |

---

## Related chapters

| Chapter | Owns |
|---|---|
| [63-LSPosed](../63-LSPosed/README.md) | **The successor.** Zygisk injection, scope, LSPlant, the API in depth |
| [13-ART](../13-ART/README.md) | `ArtMethod`, `access_flags_`, entry points, deoptimisation, hook-failure causes |
| [14-Dalvik](../14-Dalvik/README.md) | The `Method` structure the pre-ART hook used |
| [65-Hooking](../65-Hooking/README.md) | Hooking from first principles. Classic Xposed is hook type 1 |
| [62-Magisk](../62-Magisk/README.md) | Systemless root and Zygisk — the contrast |
| [61-Fastboot](../61-Fastboot/README.md) | Verified Boot, `vbmeta`, why `--disable-verity` is a corruption |
| [37-RootDetection](../37-RootDetection/README.md) · [38-TamperDetection](../38-TamperDetection/README.md) | The general detection taxonomy |
| [67-BypassingProtections](../67-BypassingProtections/README.md) | The arms race and its cost model |
| [52-StaticAnalysis](../52-StaticAnalysis/README.md) | A sweep produces leads, not findings |
