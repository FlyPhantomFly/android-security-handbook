# Useful Commands — Cheat Sheet

Printable. No prose. See [README.md](README.md) for what each command actually talks to.

---

## Connection

| | |
|---|---|
| `adb devices -l` | List devices |
| `adb kill-server && adb start-server` | Fix most connection issues |
| `adb -s <serial> <cmd>` | Target one device |
| `adb wait-for-device` | Block until ready |
| `adb get-state` | device / recovery / bootloader |
| `adb root` / `adb unroot` | Restart adbd as root (userdebug only) |
| `adb remount` | `/system` rw (needs `disable-verity` + reboot) |
| `adb reboot [bootloader\|recovery\|fastboot]` | Reboot into mode |
| `adb tcpip 5555` / `adb connect <ip>:5555` | ADB over network |
| `adb pair <ip>:<port>` | Wireless pairing (11+) |
| `adb forward tcp:27042 tcp:27042` | Host port → device port |
| `adb reverse tcp:8080 tcp:8080` | Device port → host port |

## Files

| | |
|---|---|
| `adb push <l> <r>` / `adb pull <r> <l>` | Transfer |
| `adb pull -a <r> <l>` | Preserve timestamps |
| `adb shell run-as <pkg> sh -c 'tar czf - .' > d.tgz` | Pull debuggable app data, no root |
| `adb shell "su -c 'tar czf /sdcard/d.tgz -C /data/data/<pkg> .'"` | Pull app data with root |

## Install

| | |
|---|---|
| `adb install -r app.apk` | Reinstall keep data |
| `adb install -t app.apk` | Allow testOnly |
| `adb install -d app.apk` | Allow downgrade |
| `adb install -g app.apk` | Grant all runtime perms |
| `adb install --bypass-low-target-sdk-block app.apk` | Old targetSdk (14+) |
| `adb install-multiple base.apk split_*.apk` | Split set |
| `adb uninstall [-k] <pkg>` | Remove (`-k` keeps data) |
| `adb shell pm uninstall --user 0 <pkg>` | Remove system app, no root |

## Packages

| | |
|---|---|
| `pm list packages -3` | Third-party |
| `pm list packages -s` | System |
| `pm list packages -f` | With APK path |
| `pm list packages -u` | Include uninstalled |
| `pm path <pkg>` | APK location |
| `dumpsys package <pkg>` | **Everything** — components, perms, signature, flags |
| `pm list permissions -d -g` | Dangerous perms grouped |
| `pm grant <pkg> <perm>` / `pm revoke` | Runtime perms |
| `pm clear <pkg>` | Wipe data |
| `pm disable-user --user 0 <pkg>` / `pm enable <pkg>` | Toggle |
| `pm compile -m speed -f <pkg>` | Force AOT |
| `pm list users` | Users / work profiles |

## Activities & Intents

| | |
|---|---|
| `am start -n <pkg>/<cls>` | Explicit launch |
| `am start -a <ACTION> -d <uri>` | Implicit / deep link |
| `am start -W ...` | Wait + report result |
| `am broadcast -a <ACTION> [-n <pkg>/<rcvr>]` | Broadcast |
| `am startservice -n <pkg>/<svc>` | Start service |
| `am force-stop <pkg>` / `am kill <pkg>` | Stop |
| `am crash <pkg>` | Force crash |
| `am set-debug-app -w <pkg>` / `am clear-debug-app` | Wait for debugger |
| `am monitor` | Watch crashes/ANRs |

### Extras

| Flag | Type | Flag | Type |
|---|---|---|---|
| `--es k v` | String | `--ez k true` | boolean |
| `--esn k` | String null | `--eu k <uri>` | URI |
| `--ei k 1` | int | `--ecn k pkg/.Cls` | ComponentName |
| `--el k 1` | long | `--eia k 1,2,3` | int[] |
| `--ef k 1.5` | float | `--esa k a,b,c` | String[] |
| `-f 0x10000000` | Intent flags | `--grant-read-uri-permission` | grant flag |

## Providers

| | |
|---|---|
| `content query --uri content://<auth>/<path>` | Read |
| `content query --uri <u> --projection <cols>` | injection point |
| `content query --uri <u> --where "1=1"` | injection point |
| `content query --uri <u> --sort "x"` | often-missed injection point |
| `content insert --uri <u> --bind k:s:v` | Write |
| `content call --uri <u> --method <m> --arg <a>` | RPC entry point |
| `content read --uri <u>` | path traversal test |

Bind types: `s` string · `i` int · `l` long · `f` float · `d` double · `b` bool · `n` null

## System services

| | |
|---|---|
| `dumpsys -l` | List dumpable services |
| `dumpsys window \| grep mCurrentFocus` | Current screen |
| `dumpsys activity activities` | Task/back stack |
| `dumpsys activity top` | Focused activity |
| `dumpsys activity broadcasts` | Receivers |
| `dumpsys activity services <pkg>` | Running services |
| `dumpsys meminfo <pkg>` | Memory |
| `dumpsys appops` | AppOps state |
| `dumpsys account` | Accounts |
| `dumpsys netstats` | Per-UID network |
| `service list` | All Binder services |
| `service call <name> <code> i32 1 s16 "x"` | Raw Binder transaction |
| `cmd <service> <args>` | Modern service CLI |

## Settings & properties

| | |
|---|---|
| `settings list global\|system\|secure` | Dump namespace |
| `settings put global http_proxy <ip>:<port>` | Set proxy |
| `settings put global http_proxy :0` | Clear proxy |
| `getprop` / `getprop <key>` / `setprop <k> <v>` | Properties |

### Properties to record every engagement

```
ro.build.fingerprint            ro.build.version.sdk
ro.build.version.release        ro.build.version.security_patch
ro.build.tags                   ro.build.type
ro.product.cpu.abi              ro.boot.verifiedbootstate
ro.debuggable                   ro.secure
```

## Logcat

| | |
|---|---|
| `adb logcat -c` | Clear (do this first) |
| `adb logcat -d` | Dump and exit |
| `adb logcat -v threadtime` | Best default format |
| `adb logcat --pid=$(adb shell pidof -s <pkg>)` | **Only the target app** |
| `adb logcat -b all\|crash\|events\|radio` | Buffers |
| `adb logcat *:E` | Errors+ |
| `adb logcat -G 16M` | Grow buffer |

## Process / filesystem

| | |
|---|---|
| `ps -A -o PID,USER,NAME` / `ps -Z` | Processes (`-Z` = SELinux) |
| `pidof <pkg>` | PID |
| `cat /proc/<pid>/maps` | Memory map |
| `cat /proc/<pid>/status` | UID, threads, **TracerPid** |
| `ls -l /proc/<pid>/fd` | Open FDs |
| `cat /proc/net/tcp\|tcp6\|unix` | Sockets |
| `ls -laZ /data/data/<pkg>` | App data + labels |
| `mount` / `cat /proc/mounts` | Mounts (spot Magisk) |
| `getenforce` / `id -Z` | SELinux state / context |
| `netstat -tulpn` | Listening sockets |

## APK handling

| | |
|---|---|
| `unzip -l app.apk` | Contents |
| `apktool d app.apk -o out/` | Decode |
| `apktool b out/ -o patched.apk` | Rebuild |
| `aapt2 dump badging app.apk` | Package/version/perms |
| `aapt2 dump xmltree app.apk --file AndroidManifest.xml` | Parsed manifest |
| `apksigner verify -v --print-certs app.apk` | Signature schemes + cert |
| `zipalign -p -f -v 4 in.apk out.apk` | Align (**before** signing) |
| `apksigner sign --ks k.jks out.apk` | Sign |
| `jadx -d out/ app.apk` / `jadx-gui app.apk` | Decompile |
| `baksmali d classes.dex -o smali/` / `smali a smali/ -o classes.dex` | Smali |
| `strings -a -n 8 lib/arm64-v8a/*.so` | Native strings |
| `readelf -d\|-s <so>` / `nm -D <so>` | ELF dynamic / symbols |

### Repackage cycle

```bash
apktool d target.apk -o work/
# edit work/
apktool b work/ -o patched.apk
zipalign -p -f -v 4 patched.apk aligned.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --out signed.apk aligned.apk
apksigner verify -v signed.apk
adb install -r signed.apk
```

## Frida / Objection

| | |
|---|---|
| `frida-ps -U` / `-Ua` / `-Uai` | Processes / apps / installed |
| `frida -U -f <pkg> -l s.js` | Spawn + inject |
| `frida -U -n <proc> -l s.js` | Attach by name |
| `frida -U -p <pid> -l s.js` | Attach by PID |
| `frida-trace -U -f <pkg> -i "open*"` | Trace native |
| `frida-trace -U -f <pkg> -j "com.example.*!*"` | Trace Java |
| `objection -g <pkg> explore` | Interactive |

### Inside Objection

```
android sslpinning disable
android root disable
android hooking list activities|services|classes
android hooking search classes|methods <term>
android hooking watch class_method <fqcn.m> --dump-args --dump-return --dump-backtrace
android intent launch_activity <fqcn>
android keystore list
android heap search instances <fqcn>
memory list modules|exports <mod>
env · file download <r> <l> · sqlite connect <path>
```

### frida-server setup

```bash
adb push frida-server-<ver>-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server &'"
frida-ps -U
```
Host `frida --version` **must** match the server release.

## Network

| | |
|---|---|
| `settings put global http_proxy <ip>:<port>` | Proxy on |
| `adb reverse tcp:8080 tcp:8080` | Reach host proxy over USB |
| `tcpdump -i any -s 0 -w /sdcard/cap.pcap` | Full capture (root) |
| `openssl x509 -inform PEM -subject_hash_old -in ca.pem` | CA filename hash → `<hash>.0` |

## Fastboot — destructive

| | |
|---|---|
| `fastboot devices` | List |
| `fastboot getvar all` | Variables + lock state |
| `fastboot flashing unlock` | **Wipes device** |
| `fastboot boot boot.img` | Boot **without** flashing — do this first |
| `fastboot flash boot boot.img` | Flash |
| `fastboot flash vbmeta --disable-verity --disable-verification vbmeta.img` | Disable AVB |
| `fastboot --set-active=a\|b` | A/B slot |

## Secret regexes

```
AIza[0-9A-Za-z_-]{35}                                   Google API key
AKIA[0-9A-Z]{16}                                        AWS access key id
eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+       JWT
-----BEGIN [A-Z ]*PRIVATE KEY-----                      Private key
sk_live_[0-9a-zA-Z]{24}                                 Stripe live key
xox[baprs]-[0-9A-Za-z-]+                                Slack token
https?://[a-z0-9.-]*\.firebaseio\.com                   Firebase DB
s3[.-][a-z0-9-]*\.amazonaws\.com                        S3 bucket
http://                                                 Cleartext endpoint
```
Validate every hit. A public Firebase Web API key is not a finding by itself.

## Risky API grep list

```
addJavascriptInterface            setJavaScriptEnabled
setAllowUniversalAccessFromFileURLs   setAllowFileAccessFromFileURLs
checkServerTrusted                HostnameVerifier
onReceivedSslError                SecretKeySpec
IvParameterSpec                   MODE_WORLD_READABLE
DexClassLoader                    InMemoryDexClassLoader
Runtime.getRuntime                System.loadLibrary
getExternalStorage                setWebContentsDebuggingEnabled
```

## Rules that save you

1. `shell` is UID 2000, not an app — **reproduce every finding from an unprivileged app**.
2. Align **before** sign.
3. Match frida / frida-server versions.
4. `adb logcat -c` before every reproduction.
5. Snapshot app data **before** any write operation.
6. `fastboot boot` before `fastboot flash`.
7. Record the build fingerprint and security patch level.
8. Validate every automated hit before it becomes a finding.
