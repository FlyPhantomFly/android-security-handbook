# 07 — AOSP Cheat Sheet

Printable. Tables and commands only. Full explanation in [README.md](README.md).

---

## Getting the source

```bash
mkdir -p ~/bin && export PATH=~/bin:$PATH
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo && chmod a+x ~/bin/repo

repo init -u https://android.googlesource.com/platform/manifest -b android-15.0.0_r1 --depth=1
repo sync -c -j$(nproc) --no-tags --no-clone-bundle
```

| Command | Effect |
|---|---|
| `repo info -o` | What branch/manifest is this tree on |
| `repo manifest -r -o pinned.xml` | **Pin every project to its exact SHA** — attach to reports |
| `repo forall -c 'git log --oneline -1'` | Run a command in every project |
| `repo forall -pc 'git status -s'` | Find local modifications across the tree |
| `repo start <branch> <project>` | Start a topic branch in one project |
| `repo sync --force-sync` | Recover a diverged project |
| `cat .repo/manifests/default.xml` | Remotes, defaults, projects |
| `ls .repo/local_manifests/` | **Local additions — read these on any tree you were given** |

### Manifest elements

| Element | Security meaning |
|---|---|
| `<remote fetch=...>` | Any remote that is not `android.googlesource.com` is third-party code |
| `<default revision=...>` | A branch name is mutable; a tag or SHA is not |
| `<project revision=...>` | Per-project pin |
| `<include name=...>` | Another manifest merged in — follow every one |
| `<remove-project>` / `<extend-project>` | An AOSP project replaced with a fork |

---

## Source tree map

| Directory | Contents |
|---|---|
| `art/` | Runtime, dex2oat, GC, JNI, hidden-API enforcement |
| `bionic/` | libc, libm, libdl, **the dynamic linker** |
| `build/` | Soong, Blueprint, Kati, release tooling |
| `cts/` | Compatibility Test Suite |
| `device/` | Per-device config, BoardConfig.mk, device sepolicy |
| `external/` | ~hundreds of upstream projects (boringssl, sqlite, skia, libpng) |
| `frameworks/av/` | Media framework, codecs, camera service |
| `frameworks/base/` | **The Java framework + system_server** |
| `frameworks/native/` | libbinder, SurfaceFlinger, servicemanager |
| `hardware/interfaces/` | HAL **definitions** (implementations are vendor) |
| `kernel/` | Android Common Kernel |
| `libcore/` | java.lang, java.util, javax.crypto, javax.net.ssl |
| `packages/apps/` | Settings, Launcher3, Contacts, Dialer |
| `packages/modules/` | **Mainline** modules (Permission, DnsResolver, Wifi, adb) |
| `packages/providers/` | MediaProvider, ContactsProvider, SettingsProvider |
| `prebuilts/` | Checked-in clang, JDK, every historical `android.jar` |
| `system/core/` | init, adbd, logd, debuggerd, run-as, libutils |
| `system/security/` | keystore2, identity |
| `system/sepolicy/` | SELinux policy source |
| `system/vold/` | Storage mounting and encryption |

### Inside `frameworks/base/`

| Path | Contents |
|---|---|
| `core/java/android/` | The public SDK's implementation |
| `core/java/com/android/internal/` | Internal framework classes |
| `core/jni/` | JNI backing framework classes |
| `core/res/AndroidManifest.xml` | **Every platform permission + protectionLevel** |
| `core/res/res/values/config.xml` | Platform behaviour switches OEMs override |
| `services/core/java/com/android/server/` | system_server: `am/` `wm/` `pm/` `appop/` |
| `services/java/.../SystemServer.java` | Every service, in start order |
| `core/api/current.txt` | Public SDK surface |
| `core/api/system-current.txt` | `@SystemApi` surface |
| `core/api/test-current.txt` | `@TestApi` surface |

---

## Reading AOSP — the procedure

```
1. Name a symbol you know is involved
2. Find its declaration                    (the SDK class is usually ABSTRACT)
3. Find the IMPLEMENTATION                 (*Impl, or the concrete subclass)
4. Follow the call
5. Crosses a process boundary?             -> find the .aidl
6. Find "extends I<Name>.Stub"             -> that class is in system_server
7. Find Binder.getCallingUid()             -> THAT is the check
8. Goes native?                            -> core/jni/, then the .cpp
9. Reaches the kernel?                     -> the syscall or ioctl, then the driver
```

### cs.android.com query syntax

| Query | Effect |
|---|---|
| `class:ActivityStarter` | Class declarations only |
| `function:executeRequest` | Function declarations only |
| `symbol:getCallingUid` | Declarations **and** references |
| `file:ContextImpl.java` | Restrict by filename |
| `path:frameworks/base/services` | Restrict by path prefix |
| `lang:java` / `lang:cpp` / `lang:aidl` / `lang:rust` | Restrict by language |
| `content:"Binder.getCallingUid()"` | Literal content match |
| `-path:test` | **Exclude tests — essential** |
| `case:yes` | Case-sensitive |

```
path:frameworks/base/services content:"extends IClipboard.Stub"
path:frameworks/base/services content:"Binder.getCallingUid()" -path:test
file:core/res/AndroidManifest.xml content:"INSTALL_PACKAGES"
path:frameworks/base lang:aidl
```

**Always set the branch selector (top right) to match the device you are testing.**

### Local-checkout searches

```bash
rg -n "extends I[A-Za-z]+\.Stub\b" frameworks/base/services/core/java --glob '!*/test/*'
rg -n -A25 "clearCallingIdentity" frameworks/base/services/core/java | grep -E "checkCalling|enforceCalling"
rg -n "checkCallingPermission|checkCallingOrSelfPermission" frameworks/base/services/core/java
rg -n -A3 "<permission " frameworks/base/core/res/AndroidManifest.xml
git -C frameworks/base log --oneline -S "someString"
git -C frameworks/base diff android-14.0.0_r1..android-15.0.0_r1 -- services/core/java/com/android/server/pm/
```

---

## Reading conventions

| You see | It means |
|---|---|
| `IFoo.aidl` | Generates `IFoo.Stub` (server) and `IFoo.Stub.Proxy` (client) |
| `class X extends IFoo.Stub` | **The server implementation, in system_server** |
| `FooManager` in `core/java/` | Client wrapper holding an `IFoo` proxy |
| `FooManagerService` in `services/` | The server |
| `Context` / `ContextImpl` | Abstract / real |
| `Binder.getCallingUid()` | Kernel-stamped caller identity |
| `clearCallingIdentity()` | Server acts as itself — **check BEFORE this, never after** |
| `enforce*Permission` | Throws `SecurityException` |
| `check*Permission` | Returns an int the caller might ignore |
| `Slog` | system_server logging |

---

## `@hide`, `@SystemApi`, stubs

| Annotation | In which SDK | Runtime enforcement |
|---|---|---|
| *(none)* | public | — |
| `@hide` | none | via the hidden-API blocklist |
| `@SystemApi` | system (`prebuilts/sdk/<n>/system/android.jar`) | usually a `signature\|privileged` permission |
| `@TestApi` | test | usually none |
| `@SystemApi(client=MODULE_LIBRARIES)` | module-lib | — |
| `@UnsupportedAppUsage` | none | drives blocklist generation; `maxTargetSdk` attribute |

```bash
# android.jar is STUBS — every body throws
javap -c -p -cp $ANDROID_HOME/platforms/android-35/android.jar android.content.Context | head
```

---

## Hidden-API blocklist

| List (Android 10+) | Old name | Behaviour |
|---|---|---|
| SDK | whitelist | allowed |
| unsupported | light greylist | allowed + logged |
| max-target-o/p/q/r/s | dark greylist | allowed only if `targetSdk <= X` |
| blocked | blacklist | always denied |

```bash
# adb shell — works on retail devices; shell holds WRITE_SECURE_SETTINGS
settings put global hidden_api_policy 0     # DISABLED
settings put global hidden_api_policy 1     # JUST_WARN  <- the research setting
settings put global hidden_api_policy 2     # ENABLED
settings get global hidden_api_policy
settings delete global hidden_api_policy    # reset — DO THIS before handing the device back

logcat | grep -i "Accessing hidden"

# host — for one instrumentation run only
adb shell am instrument --no-hidden-api-checks -w com.example.test/androidx.test.runner.AndroidJUnitRunner
```

Enforcement lives in `art/runtime/hidden_api.cc`, on the reflection and JNI lookup paths.

---

## Building

```bash
source build/envsetup.sh
lunch aosp_cf_x86_64_phone-trunk_staging-userdebug
m -j$(nproc)
launch_cvd --daemon --cpus 4 --memory_mb 8192
adb root
```

| Variant | `ro.debuggable` | `ro.secure` | `adb root` | SELinux |
|---|---|---|---|---|
| `user` | 0 | 1 | no | enforcing |
| `userdebug` | 1 | 1 | **yes** | enforcing |
| `eng` | 1 | 0 | yes, adbd may be root | often permissive |

| Command | Effect |
|---|---|
| `m` | Full build |
| `m <module>` | One module + dependencies |
| `m nothing` | Parse only — validates `Android.bp`, measures null-build time |
| `m snod` | **Repack `system.img` from `out/` in under a minute** |
| `m installclean` | Remove installed artefacts, keep objects |
| `stop_cvd` / `launch_cvd` | Cuttlefish lifecycle |

### `out/` tree

| Path | Contents |
|---|---|
| `out/soong/soong.variables` | **Entire product config as JSON** |
| `out/soong/build.ninja` | The generated build graph |
| `out/target/product/<d>/*.img` | Partition images |
| `out/target/product/<d>/symbols/` | **Unstripped binaries with full symbols** |
| `out/target/product/<d>/installed-files.txt` | Image inventory |
| `out/target/product/<d>/module-info.json` | Module → installed path / source dir |

---

## Device reconnaissance

```bash
# adb shell — identity
getprop ro.build.fingerprint
getprop ro.build.id
getprop ro.build.version.release
getprop ro.build.version.sdk
getprop ro.build.version.security_patch          # system partition
getprop ro.vendor.build.security_patch           # vendor partition — OFTEN MUCH OLDER
getprop ro.build.type
getprop ro.debuggable
getprop ro.secure
getprop ro.product.cpu.abilist
getenforce
uname -a

# adb shell — attack surface
service list                      # every registered Binder service
service list -l                   # with interface descriptors
dumpsys -l                        # every dumpable service
pm list packages --apex-only      # Mainline modules
pm list packages -s               # system packages
pm list permissions -d -g         # dangerous permissions by group
pm list permissions -f | grep -i vendor

# adb shell — a specific package
dumpsys package com.example.app | sed -n '/requested permissions/,/User 0/p'
dumpsys package com.example.app | grep -A2 signatures
appops get com.example.app
```

### The two-minute OEM surface diff

```bash
# On the target
adb shell service list | awk '{print $2}' | sort > oem.txt
# On a stock Pixel / Cuttlefish of the SAME release
adb shell service list | awk '{print $2}' | sort > aosp.txt
comm -23 oem.txt aosp.txt          # everything extra is vendor code as UID 1000
```

---

## Permissions and app-ops

```bash
# adb shell
pm grant  com.example.app android.permission.CAMERA
pm revoke com.example.app android.permission.CAMERA
pm reset-permissions

appops get com.example.app
appops set com.example.app CAMERA ignore     # SILENT failure — the realistic test
appops set com.example.app CAMERA allow
appops set com.example.app CAMERA default
cmd appops get com.example.app COARSE_LOCATION

logcat | grep -iE "SecurityException|Permission Denial|requires permission"
```

| Mode | Behaviour |
|---|---|
| `allow` | Operation permitted |
| `ignore` | **Silently returns nothing** — no exception |
| `deny` / `errored` | Throws |
| `default` | Falls back to the permission check |

---

## Tracing on a device

```bash
# adb shell as root — syscalls
strace -f -p $(pidof com.example.app) -e trace=openat,connect,ioctl,execve

# adb shell as root — binder at the kernel level, undetectable by apps
mount -t debugfs none /sys/kernel/debug 2>/dev/null
echo 1 > /sys/kernel/debug/tracing/events/binder/enable
cat /sys/kernel/debug/tracing/trace_pipe
echo 0 > /sys/kernel/debug/tracing/events/binder/enable

# adb shell — SELinux denials
dmesg | grep -i avc
logcat -b all | grep -i avc

# adb shell — crash and forensic artefacts
ls /data/tombstones/
ls /data/system/dropbox/
cat /data/system/packages.xml | grep -A8 "com.example.app"
cat /data/system/appops.xml
```

```javascript
// frida — every incoming Java Binder call in a process
// frida -U -n system_server -l binder-trace.js
Java.perform(function () {
    var B = Java.use("android.os.Binder");
    B.execTransact.overload('int','long','long','int').implementation =
      function (code, d, r, f) {
        console.log(this.$className + " code=" + code +
                    " uid=" + B.getCallingUid() + " pid=" + B.getCallingPid());
        return this.execTransact(code, d, r, f);
      };
});
```

---

## Patching the platform

| Goal | File |
|---|---|
| Every native Binder transaction | `frameworks/native/libs/binder/IPCThreadState.cpp` → `transact()` |
| Every incoming Java Binder call | `frameworks/base/core/java/android/os/Binder.java` → `execTransact()` |
| Every permission decision | `frameworks/base/services/core/java/com/android/server/pm/permission/` |
| Every `dlopen` | `bionic/linker/linker.cpp` |
| Every Keystore operation | `system/security/keystore2/` |

```bash
# the loop
vim frameworks/base/core/java/android/os/Binder.java
m framework          # or: m services / m libbinder
m snod               # repack system.img — under a minute
stop_cvd && launch_cvd --daemon
```

**Never report a finding from a patched image. Reproduce on stock.**

---

## Reversing an OEM framework

```bash
adb pull /system/framework/services.jar
# if it is a stub, the real DEX is in the vdex:
adb shell oatdump --vdex-file=/system/framework/oat/arm64/services.vdex \
                  --export-dex-to=/data/local/tmp/svc
jadx -d svc-oem services.jar
jadx -d svc-aosp out/target/product/<device>/system/framework/services.jar
diff -rq svc-aosp/sources svc-oem/sources          # the diff IS the vendor's code
```

```bash
# every preinstalled app, grouped by signing certificate = trust domains
for a in $(find /mnt/sys/system/priv-app /mnt/sys/system/app -name '*.apk'); do
  printf "%-60s %s\n" "$(basename $a)" \
    "$(apksigner verify --print-certs "$a" 2>/dev/null | grep -m1 'SHA-256 digest')"
done | sort -k2
```

---

## Audit patterns

| Pattern | Command |
|---|---|
| Confused deputy | `rg -n -A25 "clearCallingIdentity" <tree> \| grep -E "checkCalling\|enforceCalling"` |
| Unguarded Binder service | `rg -n "extends I[A-Za-z]+\.Stub" vendor/ device/` then check each for `enforce*` |
| Weak custom permission | `rg -n 'protectionLevel="normal"' vendor/ device/ packages/` |
| Permission with no level | `rg -n -A2 "<permission " \| grep -L protectionLevel` |
| Permissive SELinux domain | `rg -n "permissive " system/sepolicy/ device/` |
| Prebuilts with no source | `rg -n --glob 'Android.bp' "java_import\|android_app_import\|cc_prebuilt" vendor/ device/` |
| Test keys on a device | `apksigner verify --print-certs framework-res.apk \| grep -i "CN=Android"` |
| Stale vendor partition | `getprop ro.build.version.security_patch` vs `ro.vendor.build.security_patch` |

---

## CTS / VTS / GTS / STS

| Suite | Where | Public |
|---|---|---|
| CTS | `cts/` | Yes |
| CTS Verifier | `cts/apps/CtsVerifier/` | Yes |
| VTS | `test/vts*` | Yes |
| STS | built on CTS security tests | Partly |
| GTS | not in AOSP | **No** |

```bash
cts-tradefed run commandAndExit cts --module CtsPermissionTestCases
cts-tradefed run commandAndExit cts --module CtsSecurityTestCases
```

---

## Version matrix

| Android | API | Change |
|---|---|---|
| 5.0 | 21 | ART default; SELinux enforcing |
| 6.0 | 23 | Runtime permissions |
| 7.0 | 24 | User CAs untrusted by default |
| 8.0 | 26 | **Project Treble**; HIDL |
| 9 | 28 | **Hidden-API enforcement** |
| 10 | 29 | Lists renamed; **Mainline** begins; scoped storage |
| 11 | 30 | Scoped storage enforced; `<queries>` |
| 12 | 31 | `android:exported` mandatory; PendingIntent mutability |
| 13 | 33 | Granular media permissions; notification permission |
| 14 | 34 | Stricter implicit intents and dynamic receivers |
| 15 | 35 | 16 KB pages; more Mainline |
