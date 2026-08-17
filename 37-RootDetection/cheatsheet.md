# Root Detection — Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these works and what it is worth.

---

## The one-line summary

Client-side root detection is a **cost function, not a boundary**. The only control with evidence from
outside the attacker's territory is server-verified attestation ([§3.15](README.md#315-play-integrity-api--the-only-meaningful-signal)).

---

## Triage — is there root detection, and what kind?

```bash
# host
APK=app.apk
mkdir -p triage && cd triage && unzip -o "../$APK" >/dev/null

# 1. DEX strings — survives R8 renaming
for d in classes*.dex; do strings -a "$d"; done | grep -aE \
 '(^|/)su$|/system/(bin|xbin)/su|magisk|supersu|superuser|busybox|test-keys|ro\.debuggable|rootbeer|/proc/self/mounts|which su' | sort -u

# 2. Native libs — hit count per .so
for so in $(find lib -name '*.so'); do
  n=$(strings -a "$so" | grep -cE '(^|/)su$|magisk|test-keys|ro\.debuggable|/proc/self/(mounts|maps)')
  [ "$n" -gt 0 ] && echo "$so : $n"
done

# 3. Native imports — the technique, before reading any code
for so in $(find lib -name '*.so'); do
  readelf --dyn-syms "$so" 2>/dev/null | grep UND |
    grep -E ' (access|faccessat|stat|__xstat|fopen|popen|system|__system_property_get|opendir|ptrace)$' |
    sed "s|^|$so: |"
done

# 4. JNI entry points — obfuscation does NOT rename these
for so in $(find lib -name '*.so'); do readelf --dyn-syms "$so" 2>/dev/null | awk '{print $8}' | grep '^Java_'; done
```

## Verdict table

| Observation | Conclusion | Go to |
|---|---|---|
| Path strings in `classes*.dex` | Java-layer check | `java-root-bypass.js` |
| `librootbeer.so` present | RootBeer | Java methods **and** the JNI symbol |
| `access`/`stat`/`fopen` imported by an app `.so` | Native check | `native-root-bypass.js` |
| `Java_*` exports but no suspicious strings | Native + string obfuscation | tracer, then Ghidra |
| No strings anywhere, still detected | Inline syscalls | `strace`, then patch |
| `com.google.android.play:integrity` in deps | Attestation exists | Attack the integration, not the check |
| `<queries>` block listing root managers | Free list of what it hunts for | — |
| Targets API 30+, no `<queries>` | Package checks are **dead code** | Report as a finding |

## Artefact reference

### `su` and friends

```
/system/bin/su      /system/xbin/su    /sbin/su          /su/bin/su
/vendor/bin/su      /product/bin/su    /system_ext/bin/su
/data/local/su      /data/local/bin/su /data/local/xbin/su
/system/bin/.ext/su /system/bin/failsafe/su  /system/sd/xbin/su
/system/usr/we-need-root/su  /cache/su  /data/su  /dev/su
/system/xbin/busybox /system/bin/busybox /data/local/busybox
/system/app/Superuser.apk  /system/etc/init.d/  /etc/init.d/
/data/adb/magisk  /data/adb/modules  /data/adb/magisk.db
/sbin/magisk /sbin/magiskinit /sbin/magiskpolicy /sbin/.magisk /sbin/.core
/init.magisk.rc  /cache/magisk.log  /dev/com.koushikdutta.superuser.daemon/
```

### Packages

```
com.topjohnwu.magisk            com.topjohnwu.magisk.debug
eu.chainfire.supersu            com.noshufou.android.su[.elite]
com.koushikdutta.superuser      com.thirdparty.superuser      com.yellowes.su
com.devadvance.rootcloak[plus]  com.formyhm.hideroot          com.amphoras.hidemyroot
de.robv.android.xposed.installer  com.saurik.substrate
com.dimonvideo.luckypatcher     com.chelpus.lackypatch
com.kingroot.kinguser  com.kingo.root  com.smedialink.oneclickroot  com.alephzain.framaroot
com.zachspong.temprootremovejb  com.ramdroid.appquarantine
```

### Properties

| Property | Stock | Suspicious |
|---|---|---|
| `ro.build.tags` | `release-keys` | `test-keys` |
| `ro.build.type` | `user` | `userdebug`, `eng` |
| `ro.debuggable` | `0` | `1` |
| `ro.secure` | `1` | `0` |
| `ro.boot.verifiedbootstate` | `green` | `orange`/`yellow`/`red` |
| `ro.boot.flash.locked` | `1` | `0` |
| `ro.boot.veritymode` | `enforcing` | `disabled`/`logging` |
| `ro.boot.vbmeta.device_state` | `locked` | `unlocked` |
| `sys.oem_unlock_allowed` | `0` | `1` |
| `service.adb.root` | absent | `1` |
| `ro.modversion`/`ro.lineage.version` | absent | present |

Strongest local signal: `ro.boot.verifiedbootstate` — set by the bootloader, before Android exists.

### Mount table red flags (`/proc/self/mounts`)

```
/system or / mounted rw
tmpfs on /sbin, /system/bin, /system/xbin, /debug_ramdisk
overlay|overlayfs on /system*
/dev/block/loop* mounted under /system
/data/adb present at all
```

## Bypass ladder — cheapest first

| # | Step | Time | Beats |
|---|---|---|---|
| 1 | Magisk DenyList + Zygisk, force-stop, relaunch | 1 min | filesystem + mount checks |
| 2 | Add a hiding module | 5 min | property + namespace checks |
| 3 | `java-root-bypass.js` | 5 min | Java-layer checks |
| 4 | `native-root-bypass.js` | 15 min | libc-based native checks |
| 5 | `root-check-tracer.js` — identify what actually fires | 20 min | **always do before 6** |
| 6 | Targeted hook / `Memory.patchCode` | 1–3 h | inline syscalls, custom checks |
| 7 | Static patch of DEX/`.so`, re-sign | 2–6 h | persistent artefact; Frida detected |

## Frida commands

```bash
# host — ALWAYS spawn (-f). Attaching (-n) misses Application.onCreate.
frida -U -f com.target.app -l scripts/root-check-tracer.js  --no-pause
frida -U -f com.target.app -l scripts/java-root-bypass.js   --no-pause
frida -U -f com.target.app -l scripts/native-root-bypass.js --no-pause
frida -U -f com.target.app -l scripts/java-root-bypass.js -l scripts/native-root-bypass.js --no-pause

frida-trace -U -f com.target.app -i "__system_property*"
frida-trace -U -f com.target.app -i "access" -i "stat" -i "openat" -i "fopen"
frida-trace -U -f com.target.app -j 'com.target.security.*!*'
```

## Frida one-liners

```javascript
// Java: deny only root-flavoured paths (blanket false breaks the app)
Java.perform(function(){var F=Java.use("java.io.File"),B=/su$|busybox|magisk|superuser|\/sbin\/|\/data\/adb/i;
 F.exists.implementation=function(){var p=this.getAbsolutePath();return B.test(p)?false:this.exists();};});

// Java: hide root manager packages — hook the CONCRETE class
Java.perform(function(){var PM=Java.use("android.app.ApplicationPackageManager"),
 E=Java.use("android.content.pm.PackageManager$NameNotFoundException");
 PM.getPackageInfo.overloads.forEach(function(o){o.implementation=function(n){
  if(/magisk|supersu|superuser|rootcloak|xposed/i.test(n))throw E.$new(""+n);return o.apply(this,arguments);};});});

// Java: spoof properties
Java.perform(function(){var S={"ro.build.tags":"release-keys","ro.debuggable":"0","ro.secure":"1",
 "ro.boot.verifiedbootstate":"green","ro.boot.flash.locked":"1"};
 var SP=Java.use("android.os.SystemProperties");
 SP.get.overload("java.lang.String").implementation=function(k){return (k in S)?S[k]:this.get(k);};
 Java.use("android.os.Build").TAGS.value="release-keys";});

// Native: deny access() with a correct errno
var ENOENT=2,en=new NativeFunction(Module.getExportByName("libc.so","__errno"),'pointer',[]);
var a=Module.findExportByName("libc.so","access");
if(a)Interceptor.attach(a,{onEnter:function(g){this.p=g[0].readUtf8String();},
 onLeave:function(r){if(/su$|magisk|busybox/i.test(this.p||"")){en().writeS32(ENOENT);r.replace(ptr(-1));}}});

// Native: safe path substitution — allocate, never overwrite in place
var clean=Memory.allocUtf8String("/data/local/tmp/mounts.clean");
var o=Module.findExportByName("libc.so","openat");
if(o)Interceptor.attach(o,{onEnter:function(g){var p=g[1].readUtf8String();
 if(p==="/proc/self/mounts"||p==="/proc/mounts")g[1]=clean;}});

// Remove the consequence instead of the check
Java.perform(function(){Java.use("android.app.Activity").finish.implementation=function(){};
 Java.use("java.lang.System").exit.implementation=function(c){console.log("[block] exit("+c+")");};
 Java.use("android.os.Process").killProcess.implementation=function(p){};});

// Library not mapped yet — install hooks from dlopen
var d=Module.findExportByName(null,"android_dlopen_ext");
if(d)Interceptor.attach(d,{onEnter:function(a){this.p=a[0].readUtf8String();},
 onLeave:function(){if(this.p&&this.p.indexOf("libintegrity.so")!==-1)installNativeHooks();}});

// Find the aggregation point: one hook beats twenty
Java.perform(function(){Java.enumerateLoadedClasses({onMatch:function(n){
 if(/root|integrity|security|tamper/i.test(n))console.log(n);},onComplete:function(){}});});
```

## RootBeer

```javascript
// Java surface
["isRooted","isRootedWithBusyBoxCheck","isRootedWithoutBusyBoxCheck","detectRootManagementApps",
 "detectPotentiallyDangerousApps","detectRootCloakingApps","checkForSuBinary","checkForBusyBoxBinary",
 "checkForDangerousProps","checkForRWPaths","detectTestKeys","checkSuExists","checkForRootNative",
 "checkForMagiskBinary"]
// Native anchor — survives R8, resolved by name at runtime
Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot
```

## Objection

```
objection -g com.target.app explore
android root disable
android hooking list classes | grep -iE 'root|integrity|security'
android hooking watch class com.target.security.RootChecker
android hooking watch class_method com.target.security.RootChecker.isRooted --dump-backtrace
```

## `strace` — the ground truth no hook can lie about

```bash
# adb shell as root
PID=$(pidof -s com.target.app)
strace -f -p $PID -e trace=openat,faccessat,newfstatat,execve -s 200 2>&1 | grep -iE 'su|magisk|busybox|/proc/'
```

## Static patches

```smali
# smali — universal "always false" boolean method
.method public static isDeviceRooted()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
```

```text
arm64 — return 0:  MOV W0,#0 ; RET  =  00 00 80 52 C0 03 5F D6
arm64 — return 1:  MOV W0,#1 ; RET  =  20 00 80 52 C0 03 5F D6
```

```javascript
// frida — same patch at runtime, no re-signing
var t=Module.findBaseAddress("libintegrity.so").add(0x12a40);
Memory.patchCode(t,8,function(p){var w=new Arm64Writer(p,{pc:t});w.putMovRegU64('x0',0);w.putRet();w.flush();});
```

Re-signing trips [38-TamperDetection](../38-TamperDetection/README.md). Patch both or neither.

## Layer map — hook low, catch more

```
Java: new File(p).exists()
  -> libcore IoBridge / BlockGuardOs.access
    -> JNI libjavacore.so
      -> bionic libc access()      <-- Interceptor here catches Java AND native
        -> kernel faccessat        <-- inline asm bypasses everything above
Native: access(p, F_OK) ------------^
```

## Play Integrity — the three tests that find real bugs

| Test | Method | Finding if it passes |
|---|---|---|
| Replay | Capture a token from a clean device, replay it later/elsewhere | No nonce / no request binding |
| Removal | Strip the token from the request | Fail-open |
| Client evaluation | Look for JWS parsing in the app | Verdict decided client-side |

Verdicts: `MEETS_DEVICE_INTEGRITY` · `MEETS_BASIC_INTEGRITY` · `MEETS_STRONG_INTEGRITY` · empty.

## Static analysis greps

```bash
# host
jadx -d out app.apk >/dev/null 2>&1
PAT='/system/(bin|xbin)/su|/sbin/su|magisk|supersu|superuser|busybox|test-keys|ro\.debuggable|ro\.secure|verifiedbootstate|/proc/self/mounts|/proc/self/maps|RootBeer|isRooted|checkRoot|detectRoot|SystemProperties|getRuntime\(\)\.exec'
grep -rnE "$PAT" out/sources/ | tee root-hits.txt | wc -l
awk -F: '{print $1}' root-hits.txt | sed 's|/[^/]*$||' | sort | uniq -c | sort -rn | head   # <- the security package
```

## Common failure modes

| Symptom | Cause | Fix |
|---|---|---|
| Hook installs, never fires | Attached instead of spawned | `-f`, not `-n` |
| `Java.use("...PackageManager")` does nothing | Abstract class | Use `android.app.ApplicationPackageManager` |
| `Module.findExportByName` returns `null` | `.so` not mapped yet | Hook `android_dlopen_ext`, install from `onLeave` |
| Property spoof ignored | bionic used `__system_property_read_callback` | `frida-trace -i "__system_property*"` |
| App breaks in odd ways | Blanket `File.exists` → false | Narrow the regex |
| Everything hooked, still detected | Inline syscall asm | `strace`, then patch |
| Passes login, fails later | Re-check before sensitive action | Exercise the whole flow |

## Version matrix

| Behaviour | ≤ 25 | 26–29 | 30+ |
|---|---|---|---|
| Enumerate all packages | yes | yes | `<queries>` required |
| `/data/local/tmp` listable by app UID | partly | no | no |
| Magisk in `/sbin` | yes | yes | randomised tmpfs |
| SafetyNet Attestation | yes | yes | replaced by Play Integrity |
| SELinux enforcing required | yes (from 21) | yes | yes |

## Reporting

| Weak finding | Strong finding |
|---|---|
| "Root detection can be bypassed" | "Root detection is the only gate on X; after bypass, endpoint `/api/transfer` accepts the request with no server-side check" |
| "App uses RootBeer" | "The `<queries>` element is missing, so package checks never fire on API 30+; the control has never worked in production" |
| "Attestation present" | "The integrity token is not bound to the request and replays for N hours from any device" |
