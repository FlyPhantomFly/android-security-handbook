# 39 — Emulator Detection: Cheat Sheet

Measured on **Redmi M2101K6P** (Android 11 / API 30, arm64, real) and
**Pixel_6_Pro_API_35** AVD (Android 15 / API 35, x86_64). Grades are strength, not truth.

---

## Grades

| Grade | Meaning | Cost to attacker |
|---|---|---|
| HARD | Costly to fake; survives a naive Java hook | Hours–days |
| SOFT | One value, one API | Minutes |
| DEAD | **Measured not to fire** on a current AVD | Nothing |
| NOISY | Fires on real devices too | Costs the *developer* |
| INFO | Context only | — |

---

## The full signal table

| Signal | Redmi (real) | AVD (API 35) | Grade |
|---|---|---|---|
| `ro.kernel.qemu` | *unset* | `1` | SOFT |
| `ro.boot.qemu` | *unset* | `1` | SOFT |
| `ro.boot.qemu.avd_name` | *unset* | `Pixel_6_Pro_API_35` | SOFT |
| `ro.hardware` | `qcom` | `ranchu` | SOFT |
| `ro.boot.hardware` | `qcom` | `ranchu` | SOFT |
| `ro.product.board` | `sweetin` | `goldfish_x86_64` | SOFT |
| `ro.build.characteristics` | `default` | `emulator` | SOFT |
| `ro.hardware.egl` | `adreno` | `emulation` | SOFT |
| `ro.hardware.gralloc` | *unset* | `ranchu` | SOFT |
| `ro.hardware.vulkan` | `adreno` | `ranchu` | SOFT |
| `ro.soc.model` | *unset* | `ranchu` | SOFT |
| `ro.serialno` | `84f7a024` | `EMULATOR35X3X11X0` | SOFT |
| `ro.dalvik.vm.native.bridge` | `0` | `libndk_translation.so` | **HARD** |
| `ro.build.tags` | `release-keys` | `dev-keys` | NOISY |
| `ro.build.type` | `user` | `userdebug` | NOISY |
| **`qemu.hw.mainkeys`** | **`0`** | *unset* | **NOISY — inverted** |
| **`ro.kernel.qemu.gles`** | **`0`** | *unset* | **NOISY — inverted** |
| `Build.FINGERPRINT` has `generic` | false | **false** | **DEAD** |
| `Build.MODEL` has `Emulator` | false | **false** | **DEAD** |
| `Build.MODEL` has `sdk_gphone` | false | true | SOFT |
| `Build.HARDWARE` goldfish/ranchu | false | true | SOFT |
| `Build.BOOTLOADER == "unknown"` | **true** | true | **NOISY** |
| `Build.SUPPORTED_ABIS` x86 + ARM | false | **true** | **HARD** |
| `/dev/qemu_pipe` | absent | **absent** | **DEAD** |
| `/dev/socket/qemud` | absent | **absent** | **DEAD** |
| `/system/bin/qemu-props` | absent | **absent** | **DEAD** |
| `/system/bin/qemud` | absent | **absent** | **DEAD** |
| `libc_malloc_debug_qemu.so` | absent | **absent** | **DEAD** |
| `/dev/goldfish_pipe` | absent | **absent** | **DEAD** |
| `/dev/goldfish_pipe_dprctd` | absent | **present** (666) | SOFT |
| `/dev/goldfish_sync` | absent | **present** (666) | SOFT |
| `/dev/goldfish_address_space` | absent | **present** (666) | SOFT |
| `/sys/module/goldfish_pipe` | absent | **present** | SOFT |
| `/sys/bus/platform/drivers/goldfish_pipe` | absent | **present** | SOFT |
| Sensor count (app, TYPE_ALL) | **41** | **18** | HARD |
| Sensors vendored AOSP | **0/41** | **18/18** | **HARD** |
| Sensor vendors | qualcomm, TDK-Invensense, xiaomi, Rohm, akm, ams AG | AOSP, The Android Open Source Project | **HARD** |
| `/proc/cpuinfo` `hypervisor` | false | **true** | **HARD** (x86 only) |
| `/proc/cpuinfo` model name | `AArch64 Processor rev 14` | `Android virtual processor` | SOFT |
| `/proc/tty/drivers` (app) | **EACCES** | **EACCES** | **DEAD** |
| `/proc/cmdline` (app) | **EACCES** | **EACCES** | **DEAD** |
| `/proc/modules` (app) | **EACCES** | **EACCES** | **DEAD** |
| Mount entry count (app) | 263 | 156 | INFO |
| MCC/MNC | `40490` | `310260` | SOFT |
| Operator name | `airtel` | **`T-Mobile`** | **DEAD** |
| IMEI / line-1 number | privileged | privileged | **DEAD** (API 29+) |
| Visible package count (targetSdk 30) | 224 | 88 | **NOISY** |
| Feature count | 88 | **96** | **NOISY — inverted** |
| Timing, ns/iter (app uid) | **3.516** | **2.398** | **INFO — inverted** |
| Properties visible: root / shell / app | n/a / 863 / **816** | ~1062 / ~678 / **~638** | INFO |
| Emulator-named properties (app) | **2** | **26** | SOFT |
| Key attestation security level | TEE | `SOFTWARE` | **HARD** |

---

## The nine DEAD checks — memorise these

```
/dev/qemu_pipe                     Build.FINGERPRINT contains "generic"
/dev/socket/qemud                  Build.MODEL contains "Emulator"
/system/bin/qemu-props             getNetworkOperatorName() == "Android"
/system/lib/libc_malloc_debug_qemu.so   getImei() / getLine1Number()
/proc/tty/drivers  /proc/cmdline  /proc/modules   (all EACCES from an app)
```

## The inverted checks — these get it backwards

| Check | Reality |
|---|---|
| "Any `qemu`-named property means emulator" | 2 on the **real** Redmi, 0 on the AVD |
| "Emulators are slower" | AVD **1.47× faster** (2.398 vs 3.516 ns/iter) |
| "Fewer features means emulator" | AVD has **96**, phone has 88 |
| `Build.BOOTLOADER == "unknown"` | True on **both** |

---

## Quick device triage

```bash
# host - one-shot posture
S=<serial>
adb -s $S shell getprop ro.product.model
adb -s $S shell getprop ro.hardware
adb -s $S shell getprop ro.kernel.qemu
adb -s $S shell getprop ro.build.characteristics
adb -s $S shell getprop ro.product.cpu.abilist
adb -s $S shell getprop ro.dalvik.vm.native.bridge
adb -s $S shell "ls /dev | grep -iE 'qemu|goldfish'"
adb -s $S shell "grep -c hypervisor /proc/cpuinfo"
adb -s $S shell "dumpsys sensorservice | grep -m1 'h/w sensors'"
adb -s $S shell "dumpsys sensorservice | grep -cE 'AOSP|Android Open Source'"
```

## Shell vs app — always check both

```bash
# host - the trap: these numbers differ
adb -s $S shell "getprop | wc -l"                                 # shell view
adb -s $S shell "run-as <pkg> getprop | wc -l"                    # app view
adb -s $S shell getprop -Z ro.boottime.qemu-props                 # why: boottime_prop
adb -s $S shell "run-as <pkg> cat /proc/modules" 2>&1 | head -1   # EACCES from an app
```

---

## Static analysis

```bash
# host
apktool d -f -o out app.apk
jadx -d jout app.apk

# properties and Build
grep -rnE '"ro\.(kernel|boot|hardware|product|build|dalvik)\.[a-z.]+"' jout/sources/
grep -rn 'android.os.SystemProperties' jout/sources/
grep -rn 'Landroid/os/Build;->' out/smali*/

# the DEAD constants -- finding these IS the finding
grep -rnE '"generic"|"google_sdk"|"Emulator"|/dev/qemu_pipe|"15555215554"|libc_malloc_debug_qemu' jout/sources/

# device paths and /proc
grep -rnE '/dev/(qemu_pipe|socket/qemud|goldfish[a-z_]*)|/proc/(tty/drivers|cpuinfo|modules|cmdline)' out/

# sensors, packages, telephony
grep -rnE 'getSensorList|getDefaultSensor|getInstalledPackages|getNetworkOperator' jout/sources/

# native -- imports survive string encryption
for so in out/lib/*/*.so; do
  echo "== $so"
  llvm-readelf --dyn-syms "$so" | grep -E 'system_property|access|stat|open'
  strings -a "$so" | grep -aiE 'qemu|goldfish|ranchu|hypervisor|sdk_gphone'
done

# which ABIs ship at all
unzip -l app.apk | grep '\.so$' | awk '{print $4}' | cut -d/ -f2 | sort -u

# graded, automatically
python3 -B scripts/emu-signal-map.py app.apk
```

---

## Dynamic analysis

```bash
# host - ALWAYS spawn (-f), never attach (-p): checks run in static initialisers
frida -U -f com.example.app -l scripts/emu-trace.js       # trace first
frida -U -f com.example.app -l scripts/emu-bypass.js      # then neutralise selectively

# logs
adb logcat -c; adb shell am start -n <pkg>/<act>
adb logcat -d | grep -iE 'emulator|qemu|goldfish|ranchu|integrity|support'
adb logcat -d -b crash

# strace -- the one tool an app cannot hook
adb shell "su -c 'strace -f -e trace=openat,access,faccessat -p $(pidof <pkg>)'" \
    2>&1 | grep -iE 'qemu|goldfish|cpuinfo'
```

### Frida one-liners

```javascript
// properties (Java) -- affects reads AFTER the hook installs
Java.use("android.os.SystemProperties").get.overload("java.lang.String")
    .implementation = function (k) {
        return k === "ro.kernel.qemu" ? "" : this.get(k);
    };

// Build fields -- MUST write the field; the getter hook is too late
var B = Java.use("android.os.Build");
B.HARDWARE.value = "qcom";
B.MODEL.value = "M2101K6P";
B.SUPPORTED_ABIS.value = Java.array("java.lang.String",
    ["arm64-v8a", "armeabi-v7a", "armeabi"]);

// properties (native) -- what a Java hook cannot see
Interceptor.attach(Module.getExportByName("libc.so", "__system_property_get"), {
    onEnter: function (a) { this.k = a[0].readCString(); this.b = a[1]; },
    onLeave: function (r) {
        if (this.k === "ro.hardware") { this.b.writeUtf8String("qcom"); r.replace(ptr(4)); }
    }
});

// sensors -- hook the accessor, not the collection
Java.use("android.hardware.Sensor").getVendor.implementation = function () {
    var v = this.getVendor();
    return (v && v.indexOf("AOSP") >= 0) ? "qualcomm" : v;
};

// trace every emulator-ish path probe
["access","stat","open","openat"].forEach(function (fn) {
    var p = Module.findExportByName("libc.so", fn); if (!p) return;
    Interceptor.attach(p, { onEnter: function (a) {
        var i = (fn === "openat") ? 1 : 0, s;
        try { s = a[i].readCString(); } catch (e) { return; }
        if (s && /qemu|goldfish|ranchu|cpuinfo/.test(s)) console.log(fn + " " + s);
    }});
});
```

---

## Environment-side (no hooks in the app)

```bash
# device, as root, WITH Magisk -- setprop cannot change ro.* properties
resetprop ro.kernel.qemu ''
resetprop ro.hardware qcom
resetprop ro.build.characteristics default
resetprop ro.product.model M2101K6P

# or, with the before/after comparison
scripts/harden-avd.sh --apply --serial emulator-5554
scripts/harden-avd.sh --revert --serial emulator-5554   # reboots
```

**Cannot be fixed this way:** `/dev/goldfish_*` (kernel drivers), 18 AOSP sensors (the HAL),
`/proc/cpuinfo` `hypervisor` (the host CPU), absence of a TEE.

---

## Build the probes

```bash
# host - native, BOTH ABIs. The page-size flag is NOT optional on 16 KiB images.
NDK=$ANDROID_HOME/ndk/25.2.9519653/toolchains/llvm/prebuilt/<host>/bin
"$NDK/aarch64-linux-android21-clang" -Wall -Wextra -O2 \
    -Wl,-z,max-page-size=16384 -o emu_probe.arm64  examples/emu_probe.c
"$NDK/x86_64-linux-android21-clang"  -Wall -Wextra -O2 \
    -Wl,-z,max-page-size=16384 -o emu_probe.x86_64 examples/emu_probe.c

adb push emu_probe.arm64 /data/local/tmp/emu_probe
adb shell "chmod 755 /data/local/tmp/emu_probe; /data/local/tmp/emu_probe"
adb shell rm -f /data/local/tmp/emu_probe                      # clean up

# host - the app probe (no Gradle)
scripts/build-probe-app.sh --install --run --serial <serial>
scripts/build-probe-app.sh --uninstall --serial <serial>
```

Without `-Wl,-z,max-page-size=16384`, an NDK r25c binary **SIGSEGVs before `main`** on
`sdk_gphone16k_*` AVDs. Verified with `int main(void){return 42;}` exiting 139.

---

## AOSP paths

| Path | Holds |
|---|---|
| `frameworks/base/core/java/android/os/Build.java` | Build fields ← properties |
| `frameworks/base/core/java/android/os/SystemProperties.java` | The `@hide` Java API |
| `bionic/libc/system_properties/system_properties.cpp` | The trie; `__system_property_foreach` |
| `bionic/libc/include/sys/system_properties.h` | `PROP_VALUE_MAX` = **92** |
| `system/core/init/property_service.cpp` | `ro.boot.*`; `ro.` immutability |
| `system/sepolicy/private/property_contexts` | Why `boottime_prop` is app-invisible |
| `device/generic/goldfish/sensors/` | The synthetic sensor HAL |
| `frameworks/native/services/sensorservice/SensorService.cpp` | Serves the sensor list |
| `libcore/ojluni/src/main/java/java/io/File.java` | `exists()` → `faccessat` |

---

## Reverse-engineering signatures

| Layer | What to look for |
|---|---|
| JADX | `Build.FINGERPRINT.startsWith("generic")` chains — every clause measured false |
| Smali | `sget-object … Landroid/os/Build;->`, then `const-string` + `startsWith` |
| Smali | `if-nez` chain to one label = a `\|\|` short-circuit; the app never counts signals |
| Ghidra | **`char[92]`** stack buffer next to a string constant = `PROP_VALUE_MAX` = property read |
| Ghidra | `access(path, 0)` — `0` is `F_OK` |
| ELF | `__system_property_get` in `--dyn-syms` — survives string encryption |
| radare2 | `axt sym.imp.__system_property_get` — every call site at once |

---

## Severity rubric

| Situation | Rating |
|---|---|
| No detection; server has no device signal; high-value transactions | MEDIUM |
| Detection present but **DEAD**; no server control | MEDIUM |
| Detection works, bypassed in 10 min, server risk-scores independently | LOW / INFO |
| Detection false-positives on retail devices | MEDIUM |
| Server trusts a client-supplied `deviceOk` flag | **HIGH** |
| Gates a cosmetic feature | INFO |

**"Emulator detection was bypassed" is not a finding.** The finding is what the bypass gave access to
and what the server failed to do about it.

---

## Traps

| Trap | Reality |
|---|---|
| Hooking `SystemProperties.get` to change `Build.MODEL` | Fields are `static final`, latched at class-init. **Write the field.** |
| Attaching with `-p` | Checks in static initialisers / `JNI_OnLoad` already ran. Use `-f`. |
| Testing a signal from `adb shell` | The shell is uid 2000 in `u:r:shell:s0`. An app sees less. |
| `File.exists()` returning false | Could be `ENOENT` **or** `EACCES`. Java cannot tell; native can. |
| Short-circuit `\|\|` | Later checks never run. Peel one, re-trace. |
| Hook installed, nothing changed | The function may be **inlined** — zero `bl` target it. |
| Patching the APK | Re-signing trips signature verification (chapter 38). |
| A string in the DEX | Analytics SDKs read `ro.hardware` too. Cross-reference to a branch. |
| Declaring victory at the launch screen | Apps re-check at the sensitive flow. |
