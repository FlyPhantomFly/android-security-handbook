# 00 — Introduction · Cheat Sheet

Printable reference for chapter [00-Introduction](README.md). Tables and commands only.
Deeper coverage: [60-ADB](../60-ADB/README.md), [53-Frida](../53-Frida/README.md),
[62-Magisk](../62-Magisk/README.md), [35-SSL](../35-SSL/README.md).

---

## 1. Toolchain install — Windows

| Tool | Command (PowerShell, `winget` or `choco`) |
|---|---|
| JDK 17 (Temurin) | `winget install EclipseAdoptium.Temurin.17.JDK` |
| Python 3.11+ | `winget install Python.Python.3.12` |
| Git | `winget install Git.Git` |
| Android Studio | `winget install Google.AndroidStudio` |
| Platform-tools only | `choco install adb` |
| jadx | `choco install jadx` |
| apktool | `choco install apktool` |
| Burp Suite Community | `winget install PortSwigger.BurpSuite.Community` |
| Ghidra | `choco install ghidra` |
| Frida (host) | `pip install frida-tools` |
| Objection | `pip install objection` |
| MobSF | `git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF` then `.\setup.bat` |
| 7-Zip (APK/ZIP) | `winget install 7zip.7zip` |

```powershell
# host — PowerShell — persist SDK env vars for the current user
setx ANDROID_HOME "$env:LOCALAPPDATA\Android\Sdk"
setx PATH "$env:PATH;$env:LOCALAPPDATA\Android\Sdk\platform-tools;$env:LOCALAPPDATA\Android\Sdk\emulator"
```

```powershell
# host — PowerShell — verify everything resolves
java -version; python --version; adb version; jadx --version; frida --version
```

---

## 2. Toolchain install — macOS

| Tool | Command (Homebrew) |
|---|---|
| Homebrew itself | `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"` |
| JDK 17 | `brew install --cask temurin@17` |
| Python 3 | `brew install python@3.12` |
| Android command-line tools | `brew install --cask android-commandlinetools` |
| Android Studio | `brew install --cask android-studio` |
| platform-tools (adb/fastboot) | `brew install --cask android-platform-tools` |
| jadx | `brew install jadx` |
| apktool | `brew install apktool` |
| Burp Suite Community | `brew install --cask burp-suite` |
| Ghidra | `brew install --cask ghidra` |
| Frida + Objection | `pip3 install frida-tools objection` |
| MobSF | `git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF && ./setup.sh` |
| Magisk (APK, side-loaded) | download from `https://github.com/topjohnwu/Magisk/releases` |

```bash
# host — macOS — ~/.zshrc
export ANDROID_HOME="$HOME/Library/Android/sdk"
export PATH="$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin"
```

---

## 3. Toolchain install — Linux (Debian/Ubuntu)

| Tool | Command |
|---|---|
| JDK 17 | `sudo apt install -y openjdk-17-jdk` |
| Python + pip + venv | `sudo apt install -y python3 python3-pip python3-venv` |
| platform-tools | `sudo apt install -y android-sdk-platform-tools` |
| Build deps | `sudo apt install -y git unzip curl wget zipalign` |
| jadx | `sudo apt install -y jadx` or download release ZIP from GitHub |
| apktool | `sudo apt install -y apktool` |
| Burp Suite Community | download the `.sh` installer from `https://portswigger.net/burp` |
| Ghidra | download release ZIP from `https://github.com/NationalSecurityAgency/ghidra/releases` |
| Frida + Objection | `python3 -m pip install --user frida-tools objection` |
| MobSF | `git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF && ./setup.sh` |
| KVM (fast emulator) | `sudo apt install -y qemu-kvm && sudo usermod -aG kvm $USER` |

```bash
# host — Linux — ~/.bashrc
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin"
```

```bash
# host — Linux — udev rule so adb sees a physical device without root
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0664", GROUP="plugdev"' \
  | sudo tee /etc/udev/rules.d/51-android.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

---

## 4. Version pin quick reference

| Component | Known-good baseline | Why it matters |
|---|---|---|
| JDK | 17 (LTS) | apktool, jadx, Gradle, Burp all run on it |
| Android API baseline | 33–36 (Android 13–16) | This repo's target range |
| Emulator image | `google_apis` (not `google_apis_playstore`) | Play Store images block `adb root` |
| Frida host vs `frida-server` | **must match exactly** | Version mismatch causes silent attach failure |
| Python | 3.9+ | `frida-tools`, `objection`, MobSF |
| Burp Suite | Community is enough to start | Pro adds scanner and saved projects |

---

## 5. SDK manager / AVD manager / emulator

```bash
# host — list every installable package
sdkmanager --list

# host — install the essentials
sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.1" \
           "emulator" "system-images;android-35;google_apis;x86_64"

# host — accept licences non-interactively
yes | sdkmanager --licenses

# host — update everything already installed
sdkmanager --update
```

```bash
# host — AVD lifecycle
avdmanager list device
avdmanager list avd
avdmanager create avd -n pentest35 -k "system-images;android-35;google_apis;x86_64" -d "pixel_6"
avdmanager delete avd -n pentest35
```

```bash
# host — launch the emulator with a writable system and no snapshot
emulator -list-avds
emulator -avd pentest35 -writable-system -no-snapshot-load
emulator -avd pentest35 -writable-system -http-proxy 127.0.0.1:8080
emulator -avd pentest35 -wipe-data              # factory reset the AVD
emulator -avd pentest35 -gpu swiftshader_indirect   # when GPU passthrough breaks
```

```bash
# host — make /system writable on an emulator (API 29+ needs the verity dance)
adb root
adb remount
# if remount refuses:
adb shell avbctl disable-verification && adb reboot && adb root && adb remount
```

---

## 6. adb — the commands you type daily

| Command | Effect |
|---|---|
| `adb devices -l` | List attached devices with product/model detail |
| `adb kill-server` / `adb start-server` | Restart the local adb daemon on TCP 5037 |
| `adb -s <serial> <cmd>` | Target one device when several are attached |
| `adb shell` | Interactive shell on the device |
| `adb shell <cmd>` | One-shot command on the device |
| `adb root` | Restart `adbd` as root (userdebug/eng builds and most emulators only) |
| `adb unroot` | Drop back to shell user |
| `adb remount` | Mount `/system` read-write |
| `adb push <local> <remote>` | Copy host → device |
| `adb pull <remote> <local>` | Copy device → host |
| `adb install -r -t -g app.apk` | Install: replace, allow test APKs, grant all permissions |
| `adb install-multiple base.apk split_*.apk` | Install a split-APK / App Bundle set |
| `adb uninstall <pkg>` | Remove an app |
| `adb uninstall -k <pkg>` | Remove app, keep data and cache |
| `adb logcat` | Stream the system log |
| `adb reboot` / `adb reboot bootloader` / `adb reboot recovery` | Reboot targets |
| `adb tcpip 5555` then `adb connect <ip>:5555` | Switch to wireless adb |
| `adb forward tcp:27042 tcp:27042` | Host port → device port (Frida over USB) |
| `adb reverse tcp:8080 tcp:8080` | Device port → host port (proxy without Wi-Fi) |
| `adb shell screencap -p /sdcard/s.png` | Screenshot on device |
| `adb exec-out screencap -p > s.png` | Screenshot straight to the host |
| `adb shell screenrecord /sdcard/v.mp4` | Record the screen |
| `adb bugreport` | Full diagnostic bundle |
| `adb backup -f b.ab -apk <pkg>` | Legacy backup (API ≤ 30 in practice) |

### Package inspection

```bash
# adb shell — enumerate packages
pm list packages                      # all
pm list packages -3                   # third-party only
pm list packages -s                   # system only
pm list packages -f                   # with the APK path
pm list packages -e                   # enabled only
pm list packages -d                   # disabled only
pm list packages -u                   # include uninstalled-but-retained
pm list packages | grep -i bank       # filter

# adb shell — locate and describe one package
pm path com.example.app               # prints every APK path incl. splits
pm dump com.example.app | head -100
dumpsys package com.example.app
```

```bash
# host — pull an installed APK
adb shell pm path com.example.app
adb pull /data/app/~~AbCd==/com.example.app-XyZ==/base.apk .
# splits too:
for p in $(adb shell pm path com.example.app | sed 's/package://' | tr -d '\r'); do adb pull "$p"; done
```

### dumpsys / getprop / process inspection

```bash
# adb shell — dumpsys targets worth memorising
dumpsys package <pkg>          # permissions, components, signatures, install source
dumpsys activity activities    # task/back stack, current top activity
dumpsys activity top           # focused activity + its state
dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'
dumpsys -l                     # list every registered service
service list                   # every Binder service name + interface
```

```bash
# adb shell — device fingerprinting properties
getprop                            # everything
getprop ro.build.version.release   # 14
getprop ro.build.version.sdk       # 34
getprop ro.product.model
getprop ro.product.cpu.abi         # arm64-v8a / x86_64 — picks your frida-server build
getprop ro.debuggable              # 1 on userdebug/eng
getprop ro.secure                  # 0 means adbd can run as root
getprop ro.boot.verifiedbootstate  # green / orange / yellow / red
getprop | grep -i qemu             # emulator tells
```

```bash
# adb shell — processes, users, sockets
ps -A -o PID,USER,NAME | grep <pkg>   # find the app's pid and uid
id                                    # current uid/gid/SELinux context
netstat -tulpn                        # listening sockets
cat /proc/<pid>/maps                  # loaded modules and memory regions
```

### logcat filters

```bash
# host — logcat recipes
adb logcat -c                                  # clear the ring buffer first
adb logcat *:E                                 # errors and worse
adb logcat -s "MyTag"                          # single tag
adb logcat --pid=$(adb shell pidof -s com.example.app)
adb logcat -v time -b crash                    # crash buffer with timestamps
adb logcat -b all -d > full.log                # dump every buffer once and exit
adb logcat | grep -iE 'token|password|secret|authorization'
```

---

## 7. Proxy setup — Burp on the wire

| Step | Command / setting |
|---|---|
| Burp listener | Proxy → Options → add listener on `0.0.0.0:8080` |
| Device Wi-Fi proxy | Settings → Wi-Fi → modify network → Manual → host LAN IP : 8080 |
| adb alternative (no Wi-Fi) | `adb reverse tcp:8080 tcp:8080` then set proxy to `127.0.0.1:8080` |
| Emulator alternative | `emulator -avd <n> -http-proxy 127.0.0.1:8080` |
| Global proxy via adb | `adb shell settings put global http_proxy 192.168.1.10:8080` |
| Remove global proxy | `adb shell settings put global http_proxy :0` |
| Download CA from device | browse to `http://burpsuite` with the proxy active |

---

## 8. Burp CA → Android **system** certificate

Android 7.0 (API 24) stopped trusting user-added CAs for apps targeting API 24+. The certificate has
to land in the system trust store, or be injected at runtime.

```bash
# host — export the CA from Burp: Proxy → Options → Import/Export CA certificate → DER → cacert.der
openssl x509 -inform DER -in cacert.der -out cacert.pem

# host — compute the legacy hash Android uses as the filename
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
# → e.g. 9a5ba580

# host — build the file: <hash>.0 must contain PEM + human-readable text
cat cacert.pem > 9a5ba580.0
openssl x509 -inform PEM -text -in cacert.pem -noout >> 9a5ba580.0
```

```bash
# host — install into /system (emulator / rooted device with writable system)
adb root
adb remount
adb push 9a5ba580.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/9a5ba580.0
adb shell chown root:root /system/etc/security/cacerts/9a5ba580.0
adb reboot
```

```bash
# host — Android 10+ where /system is read-only: bind-mount a tmpfs copy
adb root
adb shell 'mkdir -m 700 /data/local/tmp/ca-copy'
adb shell 'cp /system/etc/security/cacerts/* /data/local/tmp/ca-copy/'
adb shell 'mount -t tmpfs tmpfs /system/etc/security/cacerts'
adb shell 'mv /data/local/tmp/ca-copy/* /system/etc/security/cacerts/'
adb push 9a5ba580.0 /system/etc/security/cacerts/
adb shell 'chown root:root /system/etc/security/cacerts/*; chmod 644 /system/etc/security/cacerts/*'
adb shell 'chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*'
```

| Route | When to use | Persistence |
|---|---|---|
| `/system/etc/security/cacerts/<hash>.0` | Emulator, `-writable-system` | Survives reboot |
| tmpfs bind-mount over cacerts | Android 10–13 rooted | Lost on reboot |
| `/apex/com.android.conscrypt/cacerts` overlay | Android 14+ (APEX trust store) | Lost on reboot |
| Magisk module (e.g. a cert-injector module) | Any Magisk device | Survives reboot, systemless |
| Frida script that patches the trust manager | Pinning present, or no root | Per-process, per-run |
| `networkSecurityConfig` + repackage the APK | Non-root, you may modify the APK | Permanent in your build |

Full treatment: [35-SSL](../35-SSL/README.md), [36-CertificatePinning](../36-CertificatePinning/README.md),
[44-NetworkSecurityConfig](../44-NetworkSecurityConfig/README.md).

---

## 9. frida-server deployment

```bash
# host — match versions exactly
frida --version                       # e.g. 16.x.y
adb shell getprop ro.product.cpu.abi  # arm64-v8a | armeabi-v7a | x86_64 | x86
# download frida-server-<version>-android-<arch>.xz from
# https://github.com/frida/frida/releases
```

```bash
# host — unpack, push, run
unxz frida-server-16.x.y-android-arm64.xz
adb push frida-server-16.x.y-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server &'"
# or on an adb-root device:
adb root && adb shell "/data/local/tmp/frida-server &"
```

```bash
# host — verify and use
frida-ps -U                 # processes on the USB device
frida-ps -Ua                # only running apps
frida-ps -Uai               # all installed apps
frida -U -f com.example.app --pause     # spawn and hold
frida -U -n com.example.app             # attach to a running process
frida -U -f com.example.app -l hook.js  # spawn with a script
frida-trace -U -n com.example.app -j 'javax.net.ssl.*!*'
```

```bash
# host — non-standard port / over TCP
adb shell "/data/local/tmp/frida-server -l 0.0.0.0:1337 &"
adb forward tcp:1337 tcp:1337
frida -H 127.0.0.1:1337 -f com.example.app
```

| Symptom | Usual cause |
|---|---|
| `Failed to enumerate processes: unable to connect` | `frida-server` not running, or wrong arch |
| `unable to communicate with remote frida-server; please upgrade` | Host/device version mismatch |
| Attaches then app dies instantly | Anti-Frida check — see [67-BypassingProtections](../67-BypassingProtections/README.md) |
| `Permission denied` on exec | Missing `chmod 755`, or SELinux denial |

Depth: [53-Frida](../53-Frida/README.md), [54-Objection](../54-Objection/README.md).

---

## 10. jadx one-liners

```bash
# host — GUI
jadx-gui app.apk

# host — decompile to Java sources
jadx -d out/ app.apk
jadx -d out/ --show-bad-code app.apk        # keep code that failed to decompile cleanly
jadx -d out/ --no-res app.apk               # skip resources, much faster
jadx -d out/ --deobf app.apk                # rename obfuscated identifiers
jadx -d out/ -e app.apk                     # also export a Gradle project skeleton
jadx --export-gradle -d out/ app.apk
jadx -d out/ classes.dex                    # a bare DEX works too

# host — grep the decompiled tree
grep -rniE "api[_-]?key|secret|password|token|http://" out/sources/
grep -rn "addJavascriptInterface\|setAllowFileAccess\|SSLSocketFactory" out/sources/
```

---

## 11. apktool / signing one-liners

```bash
# host — decode and rebuild
apktool d app.apk -o app_src               # decode: smali + resources + manifest
apktool d -s app.apk -o app_src            # keep classes.dex, do not disassemble
apktool d -r app.apk -o app_src            # keep resources.arsc raw
apktool b app_src -o app_patched.apk       # rebuild
apktool empty-framework-dir --force        # fix "framework not found" errors
```

```bash
# host — align and sign a rebuilt APK (required before install)
zipalign -p -f -v 4 app_patched.apk app_aligned.apk
keytool -genkey -v -keystore debug.keystore -alias test -keyalg RSA \
        -keysize 2048 -validity 10000 -storepass android -keypass android \
        -dname "CN=test"
apksigner sign --ks debug.keystore --ks-pass pass:android --out app_signed.apk app_aligned.apk
apksigner verify -v --print-certs app_signed.apk
adb install -r app_signed.apk
```

```bash
# host — quick APK triage without decoding
unzip -l app.apk | head -40           # list entries
unzip -o app.apk -d app_zip           # extract raw
aapt dump badging app.apk | head -20  # package name, sdk versions, launchable activity
aapt dump permissions app.apk
```

---

## 12. Key filesystem paths on a device

| Path | What lives there | Readable by |
|---|---|---|
| `/data/app/<random>/<pkg>-<random>/base.apk` | Installed third-party APKs and their splits | World-readable APK, dir traversal restricted |
| `/data/app-lib/` , `/data/app/.../lib/<abi>/` | Extracted native `.so` libraries | App + system |
| `/data/data/<pkg>/` | App private data root | The app's UID only |
| `/data/data/<pkg>/databases/` | SQLite databases | App UID |
| `/data/data/<pkg>/shared_prefs/` | XML preferences — classic secret-leak spot | App UID |
| `/data/data/<pkg>/files/` | `getFilesDir()` output | App UID |
| `/data/data/<pkg>/cache/` | `getCacheDir()` output | App UID |
| `/data/user/0/<pkg>/` | Symlink-equivalent of `/data/data/<pkg>` for user 0 | App UID |
| `/data/user_de/0/<pkg>/` | Device-encrypted storage (available pre-unlock) | App UID |
| `/data/misc/` | System daemon state | root |
| `/data/local/tmp/` | The pentester's scratch dir — `frida-server` lives here | shell user, world-ish |
| `/data/system/packages.xml` | Package DB: permissions, signatures, UIDs | root |
| `/sdcard` → `/storage/emulated/0` | Shared external storage | Any app with storage access |
| `/system/etc/security/cacerts/` | System CA trust store, files named `<subject_hash_old>.0` | read: all, write: root |
| `/apex/com.android.conscrypt/cacerts/` | Android 14+ APEX-mounted trust store | read: all, write: root |
| `/system/bin`, `/system/xbin` | System binaries — `su` here is the classic root tell | all |
| `/system/build.prop` | Build fingerprint properties | all |
| `/proc/<pid>/maps` | Loaded modules and memory regions | self / root |
| `/proc/<pid>/cmdline` | Full process name | all |
| `/dev/socket/` | Init-created UNIX sockets | varies |
| `/vendor/`, `/product/`, `/system_ext/` | Partition split introduced by Treble | all |

Depth: [33-Storage](../33-Storage/README.md), [21-App-Sandbox](../21-App-Sandbox/README.md).

---

## 13. Default ports

| Port | Service | Notes |
|---|---|---|
| 5037 | adb server (host) | `ADB_SERVER_PORT` overrides it |
| 5554 / 5555 | Emulator console / emulator adb | Even = console, odd = adb; wireless adb also uses 5555 |
| 5556, 5558, … | Additional emulator instances | Each AVD takes the next even/odd pair |
| 8080 | Burp Suite proxy listener | Default; change to avoid app-server clashes |
| 8081 | ZAP default proxy | If you run ZAP instead of Burp |
| 27042 | frida-server control port | The one `frida-ps -U` reaches |
| 27043 | frida-server auxiliary port | Historically the spawn-gating channel |
| 8000 | MobSF web UI | `http://127.0.0.1:8000` |
| 1337 | MobSF dynamic analysis / common custom Frida port | Convention, not a standard |
| 31415 | Drozer agent | `adb forward tcp:31415 tcp:31415` |
| 5900 | VNC on some emulator images | Rarely needed |
| 8554 | Emulator gRPC | Studio Device Mirroring |

---

## 14. MobSF quick start

```bash
# host — run in Docker (least painful)
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# open http://127.0.0.1:8000

# host — from source
./setup.sh          # or setup.bat on Windows
./run.sh            # or run.bat
```

```bash
# host — REST API (key is printed at startup and shown in the web UI)
curl -F "file=@app.apk" http://127.0.0.1:8000/api/v1/upload -H "Authorization: <API_KEY>"
curl -X POST http://127.0.0.1:8000/api/v1/scan -d "hash=<md5>" -H "Authorization: <API_KEY>"
curl -X POST http://127.0.0.1:8000/api/v1/download_pdf -d "hash=<md5>" -H "Authorization: <API_KEY>" -o report.pdf
```

---

## 15. Ghidra and Magisk starters

```bash
# host — Ghidra headless analysis of a native library
analyzeHeadless /path/to/project ProjName -import libnative.so -postScript MyScript.java
# GUI:
ghidraRun
```

| Magisk task | Action |
|---|---|
| Patch a boot image | Magisk app → Install → Select and Patch a File → pick `boot.img` |
| Flash the patched image | `fastboot flash boot magisk_patched.img` |
| Verify root | `adb shell "su -c id"` → expect `uid=0(root)`. Note the outer quotes |
| Hide root from an app | Magisk app → Settings → Configure DenyList → tick the package |
| Enable Zygisk | Magisk app → Settings → Zygisk → reboot |
| Install a module | Magisk app → Modules → Install from storage |

Depth: [62-Magisk](../62-Magisk/README.md), [61-Fastboot](../61-Fastboot/README.md), [57-Ghidra](../57-Ghidra/README.md).

---

## 16. Career ladder

| Level | Typical title | Years | What you are expected to do | Proof of ability |
|---|---|---|---|---|
| 0 | Learner / student | 0–1 | Set up a lab, take an APK apart, read Smali slowly | Finished DIVA, InsecureBankv2, AndroGoat |
| 1 | Junior / Associate Pentester | 1–2 | Run a checklist-driven mobile test with supervision | MASTG-aligned test of a real app, written up |
| 2 | Mobile Pentester | 2–4 | Own an engagement end to end; bypass pinning and root detection unaided | Clean reports, repeat client work, first CVEs or bounties |
| 3 | Senior Mobile Pentester | 4–7 | Reverse native code, chain findings, argue exploitability, mentor juniors | Complex chains, custom tooling, conference talks |
| 4 | Mobile Security Researcher | 6+ | Find novel bugs in platform or SDKs, not just apps | Accepted CVEs, AOSP/vendor acknowledgements |
| 5 | Principal / Lead | 8+ | Set methodology, build the practice, define what the team tests | Published research, internal tooling used by others |

| Adjacent path | Where it goes |
|---|---|
| Mobile AppSec Engineer | Inside a product company: SDLC, threat models, secure-by-default libraries |
| Malware / Threat Analyst | Family triage, C2 extraction, detection engineering — see [69-MalwareAnalysis](../69-MalwareAnalysis/README.md) |
| Exploit Developer | Kernel and TEE bugs, weaponisation — see [70-VulnerabilityResearch](../70-VulnerabilityResearch/README.md) |
| Bug Bounty Hunter | Independent, income is variable, ceiling is uncapped |
| DFIR (mobile forensics) | Acquisition, artefact parsing, court-grade documentation |

---

## 17. Legal jurisdiction quick table

> Reference only. This is not legal advice. Get written authorisation before every engagement.

| Jurisdiction | Instrument | Core prohibition | Practical rule for you |
|---|---|---|---|
| United States | Computer Fraud and Abuse Act, 18 U.S.C. §1030 | Access without authorisation or exceeding authorised access | Scope document = authorisation. Never touch out-of-scope hosts |
| United States | DMCA §1201 | Circumventing technological protection measures | A security-research exemption exists but is narrow and periodically renewed |
| United Kingdom | Computer Misuse Act 1990, ss.1–3A | Unauthorised access; unauthorised acts impairing operation; making/supplying hacking tools | Tool development is legal for legitimate purpose; intent and context matter |
| India | Information Technology Act 2000, §43 | Unauthorised access, downloading, damage — civil liability | Damages payable to the affected party |
| India | Information Technology Act 2000, §66 | Dishonest or fraudulent §43 acts — criminal | Imprisonment and/or fine |
| European Union | Directive 2013/40/EU on attacks against information systems | Harmonised offences across member states | Implemented in each state's own criminal code |
| European Union | GDPR (Regulation 2016/679) | Processing of personal data | Real user data pulled during testing is personal data — minimise, encrypt, delete |
| Singapore | Computer Misuse Act | Unauthorised access and modification | Extraterritorial reach is explicit |
| Australia | Criminal Code Act 1995, Part 10.7 | Unauthorised access/modification/impairment | Similar structure to the UK CMA |
| Canada | Criminal Code s.342.1 | Unauthorised use of a computer | Includes possession of device/tool for that purpose |

| Situation | Verdict |
|---|---|
| Testing an app you wrote | Fine |
| Testing a deliberately vulnerable training app | Fine |
| Decompiling an app you legally installed, for your own study | Generally fine; the EULA may still forbid it |
| Testing a live production app with no programme and no contract | Crime in every row above |
| Testing inside a bug bounty scope, following its rules | Authorised — keep the scope page saved and dated |
| Testing an app that is in-scope, against another user's account | Almost always out of scope. Use your own test accounts |
| Publishing a bypass for a real app's protections without disclosure | Legally and ethically risky |

---

## 18. Failure modes and their fixes

| Symptom | First thing to check |
|---|---|
| `adb devices` shows `unauthorized` | Accept the RSA prompt on the device; `adb kill-server` and replug |
| `adb devices` shows nothing | USB debugging off, cable is charge-only, missing udev rule / OEM driver |
| `adb root` says "cannot run as root in production builds" | You are on a user build. Use an emulator `google_apis` image or Magisk |
| Burp shows no traffic | App does not honour the proxy, or uses a raw socket / gRPC / WebSocket |
| Burp shows TLS errors only | Certificate not trusted at system level, or pinning is active |
| Traffic works in the browser, not in the app | `networkSecurityConfig` restricts trust anchors |
| Frida attaches then the app exits | Anti-instrumentation check on `/data/local/tmp` or port 27042 |
| `apktool b` fails on resources | Framework mismatch: `apktool empty-framework-dir --force`, then re-decode |
| Rebuilt APK will not install | Not zipaligned, not signed, or signature differs from the installed copy |
| jadx output is empty or garbled | Obfuscation or a packer; fall back to Smali and native analysis |
| Emulator boots to a black screen | Try `-gpu swiftshader_indirect`, or `-wipe-data` |
