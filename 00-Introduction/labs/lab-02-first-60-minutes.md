# Lab 02 — Your First 60 Minutes

> **Difficulty:** Beginner · **Time:** 60–90 minutes · **Chapter:** [00 — Introduction](../README.md)

This is the lab where Android stops being an abstraction. You are going to take an application that
is running on a real Android system, copy its installed package back to your machine, open it with
nothing more exotic than an unzip utility, and look at what an app *is* on disk. Nothing here is a
technique you will keep using unchanged for years — it is the map you need before any of the later
techniques mean anything.

> **Mental Model.** An installed Android app is a sealed shipping container. It has a manifest
> stapled to the outside declaring what is inside and what the container is allowed to do, a cargo
> hold of compiled code, a crate of pre-translated text and images, and a tamper seal. In this lab
> you locate the container, take a copy of it, cut the shrink-wrap, and inventory the contents. You
> do not yet care what the code *says* — only that you can see the boxes and name them.

---

## Objective

Starting from a machine that has `adb`, `unzip`, and `jadx` (built in
[Lab 01](lab-01-build-your-lab.md)), you will:

1. Obtain a running Android system, either an emulator you create or a physical device you connect.
2. Enable Developer Options and USB debugging, and understand what that switch actually turns on.
3. Confirm host-to-device communication with `adb devices`.
4. Enumerate the installed packages and distinguish user-installed apps from system apps.
5. Resolve a package name to its APK path on the device filesystem with `pm path`.
6. Copy that APK to your host with `adb pull`.
7. Treat the APK as a ZIP archive, unpack it, and identify every top-level artefact inside.
8. Open the same APK in `jadx` and read one decompiled class end to end.

---

## Prerequisites

- [Lab 01 — Build Your Lab](lab-01-build-your-lab.md) completed, with `adb`, `unzip`, and `jadx`
  verified working.
- Either a physical Android phone you personally own, or 12 GB of free disk for an emulator.
- No knowledge of Java, Android, or reverse engineering. Terms are defined as they appear.

> **Warning — legality.** Pull APKs only from devices you own and from apps you are permitted to
> analyse. In this lab, use either an app you wrote, a deliberately vulnerable training app, or a
> pre-installed AOSP app on an emulator. [Lab 03](lab-03-legal-scope-triage.md) covers where the
> boundary sits and which statute applies where you live. Read it before you point these commands at
> anything commercially interesting.

---

## Setup

### Option A — an Android Virtual Device (recommended for your first run)

> **Definition — AVD.** An *Android Virtual Device* is a configuration describing a virtual
> phone: its screen, its CPU architecture, the amount of RAM, and which **system image** (a full
> Android OS build) it boots. The emulator process runs that image under hardware-assisted
> virtualisation on your host. It is a real Android system, not a simulator that fakes API responses.

Install Android Studio, open its **Device Manager**, and create a device. The choices that matter
for security work are the ones people usually skip past:

| Setting | Choose | Why it matters |
|---|---|---|
| Device profile | Pixel 6 or Pixel 7 | Pixel profiles match real Google hardware, so behaviour matches what you will see on a real phone |
| System image | A **Google APIs** image, *not* "Google Play" | Google APIs images have a `root`-capable `adb`; Play images are production-signed and `adb root` is refused |
| API level | 33 or 34 to start | Recent enough to be realistic, old enough that most tooling is stable against it |
| ABI | `x86_64` on Intel/AMD hosts, `arm64-v8a` on Apple Silicon | An ABI mismatch causes `INSTALL_FAILED_NO_MATCHING_ABIS` when you install real-world APKs |

> **Definition — ABI.** An *Application Binary Interface* is the contract describing how compiled
> machine code is laid out and how functions call each other on a given processor family. Android's
> ABI names are `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`. Java code in an APK is
> architecture-independent; native `.so` libraries are not, and are shipped once per ABI — which is
> why the `lib/` directory you will find later has one subdirectory per ABI.

You can also create and launch an AVD entirely from the command line:

```bash
# host — download an image, create the AVD, and boot it
sdkmanager "system-images;android-35;google_apis;x86_64"
avdmanager create avd -n pentest-35 -k "system-images;android-35;google_apis;x86_64" -d pixel_6
emulator -avd pentest-35 -wipe-data -no-boot-anim
```

> **Pentester's Note.** An emulator is the right place to *learn* and the wrong place to
> *conclude*. Many production apps detect emulators and change behaviour, and hardware-backed
> KeyStore, StrongBox, and biometric behaviour differ fundamentally from real silicon. Findings
> demonstrated only on an emulator will be challenged, correctly, by the client's engineers. See
> [39 — Emulator Detection](../../39-EmulatorDetection/README.md) and
> [50 — Hardware-Backed Security](../../50-HardwareBackedSecurity/README.md).

### Option B — a physical device

Use a device you own outright and are willing to factory-reset. A used Google Pixel is the standard
research phone because its bootloader can be unlocked officially and AOSP builds and Magisk support
it well; the rooting workflow itself is covered in [62 — Magisk](../../62-Magisk/README.md), and is
not required for this lab. Everything below works on an unrooted, locked device.

---

## Steps

### Step 1 — Enable Developer Options

Android hides its developer settings behind a deliberate obscurity: you must tap a build number
seven times. This is not security, it is a speed bump to stop ordinary users from being talked into
enabling debugging by a phone scammer.

1. Open **Settings → About phone**.
2. Find **Build number**. On some vendor skins it lives under *Software information*.
3. Tap it seven times. A toast counts down, then announces "You are now a developer".
4. Go back to **Settings → System → Developer options**.

### Step 2 — Enable USB debugging and understand what it does

In **Developer options**, turn on **USB debugging**.

> **Definition — USB debugging.** Enabling this starts `adbd`, the ADB daemon, on the device and
> allows it to accept connections from an authorised host. `adbd` runs as the `shell` user on a
> production build. The `shell` user is a real Unix account on the device with its own UID, its own
> set of granted permissions, and considerably more privilege than a normal app — it can list all
> packages, read logs, install and uninstall software, and read world-readable parts of the
> filesystem. It is *not* root, and on a production build it cannot read another app's private data
> directory.

> **Warning.** Leaving USB debugging enabled on a phone you carry is a genuine risk, not a
> theoretical one. A host that has been authorised once keeps a key on the device and can reconnect
> silently. Malicious charging hardware exploits exactly this. Turn it off when you are not testing,
> and use **Revoke USB debugging authorisations** in Developer options after an engagement.

Connect the device by USB. Use a cable that carries data — many charging cables do not, and the
resulting symptom is an empty device list with no error at all.

### Step 3 — Confirm the connection

```bash
# host — expected output shown below the command
adb devices -l
#   List of devices attached
#   emulator-5554   device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64
```

The first time you run this after connecting, the device shows an "Allow USB debugging?" dialog
containing your host's RSA key fingerprint. Accept it, and tick "Always allow from this computer" if
this is your own machine.

| State shown | Meaning | What to do |
|---|---|---|
| `device` | Connected and authorised. Proceed. | Nothing |
| `unauthorized` | The RSA prompt was not accepted, or was dismissed | Unlock the screen and accept the dialog |
| `offline` | `adbd` is restarting, or the connection is half-open | `adb kill-server && adb start-server`, replug |
| `no permissions` (Linux) | The `udev` rules do not grant your user access to the USB device | Install `android-sdk-platform-tools-common`, or add a `udev` rule, then replug |
| Nothing listed | Charge-only cable, USB debugging off, or a driver issue on Windows | Change cable, re-check the toggle, install the OEM USB driver |

> **Under the Hood.** `adb devices` does not talk to the device directly. Your `adb` client
> connects over a local TCP socket to the ADB *server* on `127.0.0.1:5037`, and that server owns the
> USB endpoints and any TCP-connected devices. This is why `adb kill-server` fixes so many
> unexplained states: it discards the server's entire notion of the world and rebuilds it. The
> protocol's framing and the authentication handshake are covered in
> [60 — ADB](../../60-ADB/README.md).

### Step 4 — Get a shell on the device

Running `adb shell` with no arguments drops you at a prompt on the device. Android's userspace is
Linux, so the commands you know mostly work, provided by `toybox` rather than GNU coreutils.

```bash
# adb shell — who am I, and on what?
id
getprop ro.build.version.release
getprop ro.build.version.sdk
getprop ro.product.cpu.abi
```

`id` prints something like `uid=2000(shell) gid=2000(shell) ...`. UID 2000 is `shell`. Every app on
the device gets its own UID in the 10000+ range, and that per-UID separation *is* the Android
sandbox — the subject of [21 — App Sandbox](../../21-App-Sandbox/README.md).

The repository ships a commented script that runs this whole enumeration for you:

```bash
# host — from the repository root
sh 00-Introduction/examples/hello-adb.sh
```

Type `exit` to return to your host shell.

### Step 5 — List the installed packages

> **Definition — package name.** Every Android app is identified by a *package name*, a
> reverse-DNS string such as `com.android.settings`. It is the app's primary key: two apps with the
> same package name cannot coexist on one device, and the package name plus the signing certificate
> together determine update eligibility. It is *not* the app's display name, and the two frequently
> have nothing to do with each other.

```bash
# host
adb shell pm list packages                      # everything
adb shell pm list packages -3                   # third-party only — usually what you want
adb shell pm list packages -f                   # include the APK path
adb shell pm list packages | grep -i calculator # search
```

| Flag | Effect |
|---|---|
| `-3` | Third-party packages only — installed by the user or by you |
| `-s` | System packages only — shipped in the system image |
| `-f` | Print the APK path with each package |
| `-d` | Disabled packages only |
| `-e` | Enabled packages only |
| `-u` | Include uninstalled-but-retained packages |
| `--user <id>` | Restrict to one Android user profile (0 is the primary user) |

Pick a target, and **confirm it exists on your image before you use it** — do not copy a package
name out of a tutorial, this one included. Recent system images ship a different app set from older
ones: `com.android.calculator2` is present on many older AVDs and is **absent** on the
`sdk_gphone16k_x86_64` API 35 image, where `pm list packages | grep -i calculator` returns nothing
at all. `com.android.settings` is present on effectively every image and is the safest default. If
you have installed a training app such as an intentionally vulnerable APK, use that instead.

### Step 6 — Resolve the package to its APK path

```bash
# host — resolve a package you have confirmed is installed
adb shell pm path com.android.settings
#   package:/system_ext/priv-app/SettingsGoogle/SettingsGoogle.apk
```

If `pm path` prints nothing, the package is not installed under that exact name — go back to
`pm list packages` and search again. An empty result is not an error message, and it is the single
most common way to lose ten minutes at this step.

The path tells you a great deal before you open anything:

| Path prefix | Meaning |
|---|---|
| `/data/app/...` | Installed by the user or by `adb install`. Writable partition, upgradable |
| `/system/app`, `/system/priv-app` | Shipped in the read-only system image. `priv-app` holds *privileged* apps that may hold signature-or-privileged permissions |
| `/system/product/app`, `/system_ext/...`, `/vendor/app` | Partitions introduced by Project Treble to separate Google, OEM, and silicon-vendor content |
| Multiple lines returned | The app is a **split APK** — see the note below |

> **Definition — split APK.** Since Android 5.0 an application can be installed as several APK
> files that the runtime treats as one app: a `base.apk` plus configuration splits for a specific
> screen density (`split_config.xxhdpi.apk`), a language (`split_config.en.apk`), or an ABI
> (`split_config.arm64_v8a.apk`). Apps distributed as Android App Bundles are almost always
> installed this way. If you pull only `base.apk` from such an app, you will be missing native
> libraries and resources and will waste an afternoon wondering why. The repository's
> [`pull-apk.sh`](../scripts/pull-apk.sh) script handles all splits automatically.

### Step 7 — Pull the APK to your host

```bash
# host — work in a dedicated directory; never dump analysis output into your home directory
mkdir -p ~/work/lab02 && cd ~/work/lab02
adb pull /system_ext/priv-app/SettingsGoogle/SettingsGoogle.apk ./target.apk
#   ...SettingsGoogle.apk: 1 file pulled, 0 skipped. 55.9 MB/s

# or do the whole resolve-and-pull in one step, from the repository root:
sh 00-Introduction/scripts/pull-apk.sh com.android.settings ~/work/lab02
```

Use the path **your** `pm path` printed, not the one above — it differs between images.

> **Warning — Git Bash on Windows rewrites device paths.** If you are on Windows in Git Bash or
> MSYS2 (which [Lab 01](lab-01-build-your-lab.md) suggests), the shell converts any argument that
> looks like a Unix absolute path into a Windows one *before* `adb` sees it, so the command above
> fails with
> `adb: error: failed to stat remote object 'C:/Program Files/Git/system_ext/...'`. The device path
> never reached the device. Prefix the command with `MSYS_NO_PATHCONV=1`, or run it from PowerShell
> or `cmd`:
>
> ```bash
> # host — Git Bash / MSYS2 on Windows
> MSYS_NO_PATHCONV=1 adb pull /system_ext/priv-app/SettingsGoogle/SettingsGoogle.apk ./target.apk
> ```
>
> The same applies to every `adb pull`, `adb push` and `adb shell <absolute-path>` in this
> repository. WSL, macOS and Linux are unaffected.

Record the hash immediately. An APK's SHA-256 is the identifier you will quote in a report, and it
is the only way to prove six months later that you analysed the same binary the client shipped.

```bash
# host — Linux: sha256sum · macOS: shasum -a 256 · Windows: Get-FileHash -Algorithm SHA256
sha256sum target.apk
```

### Step 8 — Open the APK as a ZIP

> **Definition — APK.** An *Android Package* is an ordinary ZIP archive with a mandated internal
> layout and a signature block. There is no proprietary container, no encryption, and no obfuscation
> at the container level. Renaming it to `.zip` changes nothing about the file; it only changes what
> your operating system offers to open it with. The full format, including the signing schemes, is
> [10 — APK Internals](../../10-APK-Internals/README.md).

```bash
# host — always list before you extract
unzip -l target.apk | head -40
mkdir -p extracted && unzip -q target.apk -d extracted
ls -la extracted
# Windows equivalent: Expand-Archive -Path .\target.apk -DestinationPath .\extracted

# the repository's inventory tool groups and measures the entries for you
python3 00-Introduction/examples/apk-anatomy.py ~/work/lab02/target.apk
```

### Step 9 — Identify every artefact you found

This is the substance of the lab. Do not skip to `jadx` until you can name each of these.

| Entry | What it is | Why an attacker cares |
|---|---|---|
| `AndroidManifest.xml` | The app's declaration of identity, components, permissions, and configuration — stored in *binary* XML, not text | It is the complete inventory of the app's attack surface: every exported component, every permission, every deep link. See [32 — Manifest](../../32-Manifest/README.md) |
| `classes.dex`, `classes2.dex`, … | The compiled Java/Kotlin code, in Dalvik Executable format. Multiple files appear when the app exceeds the 65,536-method limit of a single DEX | This is the application logic. Every decompiler, every static analyser, and every Frida Java hook ultimately targets this. See [12 — DEX Internals](../../12-DEX-Internals/README.md) |
| `resources.arsc` | A compiled binary table mapping resource IDs to values, per configuration (language, density, API level) | Hardcoded URLs, API keys committed as string resources, and feature flags live here. It is not compressed and not encrypted |
| `res/` | Compiled resources: layouts, drawables, XML files. The XML here is binary-encoded, like the manifest | Layouts reveal hidden UI and debug screens; `res/xml/` often holds the network security config |
| `assets/` | Arbitrary files the developer shipped verbatim, untouched by the build system | This is where teams hide things they think nobody will look at: bundled JavaScript, ML models, configuration JSON, even secondary DEX files loaded at runtime |
| `lib/<abi>/*.so` | Native shared libraries, one directory per ABI | Crypto implementations, root-detection routines, and anti-tamper checks are pushed into native code precisely because it is harder to read. See [15 — Native Code](../../15-Native-Code/README.md) |
| `META-INF/` | Signature material: `MANIFEST.MF`, `*.SF`, `*.RSA`/`*.DSA` for v1 (JAR) signing, plus `com.android.support_*.version` style marker files | The presence of `*.SF` files tells you v1 signing is in use. v2/v3/v4 signatures live in a block *before* the ZIP central directory, not inside the archive tree |
| `kotlin/`, `DebugProbesKt.bin` | Kotlin metadata | A quick tell that the app is written in Kotlin, which changes what the decompiled output looks like |

Now try to read the manifest as text. You will see binary data beginning with a small header rather
than `<?xml`, because Android compiles XML into a binary format (AXML) with a string pool and typed
nodes, for parsing speed and size. Turning it back into text is what `apktool` does.

```bash
# host — the first command deliberately produces garbage; that is the lesson
head -c 200 extracted/AndroidManifest.xml | xxd | head -10
apktool d target.apk -o decoded
head -30 decoded/AndroidManifest.xml
```

> **Under the Hood.** AXML begins with a chunk header: a 16-bit type, a 16-bit header size, and a
> 32-bit chunk size, followed by a string pool chunk and then the element tree. Attribute values are
> typed, so `android:exported="true"` is stored as a boolean, not as the string "true". Malformed
> AXML has repeatedly been used to confuse parsers — one class of attack ships a manifest that the
> platform parser and the analysis tool disagree about. The format is dissected in
> [10 — APK Internals](../../10-APK-Internals/README.md).

### Step 10 — Decompile and read one class

```bash
# host — GUI: opens a browsable tree of decompiled Java
jadx-gui target.apk

# host — CLI: writes sources and resources to ./out
jadx -d out target.apk
```

`jadx` will print warnings. Warnings are normal — decompilation is a lossy reconstruction, and some
methods will come out as commented-out bytecode. That is not a failure of your setup.

Now do the thing that actually matters: **read one class from top to bottom.** Find the launcher
activity in the decoded manifest — it is the `<activity>` whose `<intent-filter>` contains the
action `android.intent.action.MAIN` and the category `android.intent.category.LAUNCHER`. That
element's `android:name` attribute is the class the system instantiates when the user taps the icon.

Open the corresponding file under `out/sources/`, find `onCreate`, and follow it. You are not
looking for a vulnerability. You are answering four questions:

1. Where does execution begin when the user taps the icon?
2. What does the class extend, and what does that parent class provide?
3. Where does data enter this class from outside the app?
4. Which of the strings in this file were written by a human, and which were generated?

Compare what you read against [`FirstApp.java`](../examples/FirstApp.java) in this chapter, which is
a minimal annotated Activity showing exactly the constructs you are looking at.

---

## Hints

- If `adb devices` shows nothing on Linux, the problem is almost always `udev` permissions rather
  than the device. Run `lsusb` — if the device appears there, the kernel sees it and only your
  user's access is missing.
- `pm path` returning nothing means the package name is wrong. Package names are case-sensitive and
  are not the app's display name. Use `pm list packages | grep -i <fragment>` to find the real one.
- `adb pull` on a path under `/data/data/` fails with `Permission denied` on an unrooted device.
  That is the sandbox working correctly, not a broken setup. Installed APKs under `/data/app/` are
  world-readable, which is why pulling those works.
- `jadx-gui` failing to start with a Java error is a `JAVA_HOME` problem, not a `jadx` problem. See
  the troubleshooting table in [Lab 01](lab-01-build-your-lab.md).

---

## Solution

The complete command sequence, condensed. Substitute your own package name.

```bash
# host — end-to-end walkthrough
adb devices -l                                   # 1. confirm the device is visible and authorised
adb shell getprop ro.build.version.release       # 2. what Android version am I on
adb shell pm list packages -3                    # 3. what user-installed apps exist
adb shell pm path com.example.target             # 4. where does that app live on disk
mkdir -p ~/work/lab02 && cd ~/work/lab02
adb pull /data/app/~~AbC==/com.example.target-xY==/base.apk ./target.apk
sha256sum target.apk                             # 5. record the identity of what you analysed
unzip -l target.apk                              # 6. inventory without extracting
mkdir extracted && unzip -q target.apk -d extracted
apktool d target.apk -o decoded                  # 7. decode binary XML and produce Smali
jadx -d out target.apk                           # 8. decompile DEX to Java
```

### What each stage produced, and what it means

| Stage | Output | Interpretation |
|---|---|---|
| `pm path` | One or more `package:` lines | One line means a monolithic APK; several mean splits, and you need all of them |
| `sha256sum` | A 64-character hex digest | Your evidence anchor for the report |
| `unzip -l` | An entry listing with sizes | `lib/` present means native code exists; multiple `classes*.dex` means a large codebase |
| `apktool d` | Readable `AndroidManifest.xml` and `smali/` | Smali is human-readable assembly for DEX, and it is what you edit when you patch |
| `jadx -d` | `out/sources/` and `out/resources/` | Readable Java for understanding, plus a decoded manifest |

A minimal correct inventory of a typical release APK looks like this:

```text
# host — unzip -l output, abridged
     5432  1981-01-01 01:01   AndroidManifest.xml
  4218904  1981-01-01 01:01   classes.dex
  2109448  1981-01-01 01:01   classes2.dex
   882176  1981-01-01 01:01   resources.arsc
  1904128  1981-01-01 01:01   lib/arm64-v8a/libnative.so
     1211  1981-01-01 01:01   META-INF/CERT.SF
     1401  1981-01-01 01:01   META-INF/CERT.RSA
```

The `1981-01-01` timestamps are not a bug and not evidence of tampering. Build tools normalise ZIP
entry timestamps so that identical inputs produce byte-identical outputs — a property called
reproducible builds. Noticing that and knowing why is the difference between a report that says
"suspicious timestamps observed" and one that says something true.

---

## Success Criteria

You have completed this lab when you can, without notes:

1. Explain what enabling USB debugging turns on, and which Unix user `adbd` runs as on a production
   build.
2. Go from a package name to a local copy of the APK in three commands.
3. Name every top-level entry in an APK and state in one sentence why each one is interesting to an
   attacker.
4. Explain the difference between what `apktool` produces and what `jadx` produces, and say which
   one you would use to patch an app and which to understand one.
5. Show the SHA-256 of the APK you analysed, recorded in your notes.
6. Point at the launcher activity in the manifest and then at its decompiled source file.

---

## Going Further

- **Diff two versions of the same app.** Pull an app, update it, pull it again, and compare the
  entry listings and hashes. Reading a diff between releases is the core skill behind patch-gap
  research — see [70 — Vulnerability Research](../../70-VulnerabilityResearch/README.md).
- **Find the network security config.** Look for `res/xml/network_security_config.xml` in the
  decoded output and read it. It decides whether your intercepting proxy will work at all — see
  [44 — Network Security Config](../../44-NetworkSecurityConfig/README.md).
- **Grep the assets.** Run `grep -rIn "http" decoded/assets/ decoded/res/` and look at what falls
  out. This crude search finds real endpoints in real apps far more often than it should.
- **Repack and reinstall.** Use `apktool b decoded -o patched.apk`, sign it with a debug key, and
  install it. It will fail in interesting ways the first time, and understanding why is the whole of
  [10 — APK Internals](../../10-APK-Internals/README.md) and
  [38 — Tamper Detection](../../38-TamperDetection/README.md).
- **Read the DEX header by hand.** `xxd -l 112 extracted/classes.dex` shows the magic `dex\n035`,
  the Adler-32 checksum, the SHA-1 signature, and the offsets to every section —
  [12 — DEX Internals](../../12-DEX-Internals/README.md) walks through each field.

---

**Next:** [Lab 03 — Legal Scope Triage](lab-03-legal-scope-triage.md) — before you point any of this
at something that matters, learn where the line is.
