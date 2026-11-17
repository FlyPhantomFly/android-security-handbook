# Lab 02 — Unpack, Modify, Rebuild, Re-sign

**Difficulty:** Intermediate
**Time:** 90–150 minutes
**Chapter:** [10-APK-Internals](../README.md)
**Builds on:** [Lab 01 — Dissecting the APK, Byte by Byte](lab-01-dissecting-the-apk-byte-by-byte.md)

---

> ## Read this before you start: what is measured here, and the trap that nearly broke it
>
> **Every `apktool` and `apksigner` console block in this lab is real output from the machine this
> lab was written on.** That is worth stating explicitly, because an earlier revision of this file
> claimed the exact opposite — and how it got there is a lesson worth more than the transcripts.
>
> ### "command not found" is not "not installed"
>
> On Windows, `apktool` and `apksigner` are `.bat` shims. **Git Bash does not append `.bat` when it
> resolves a bare name, so it finds nothing — while cmd and PowerShell resolve both instantly:**
>
> ```powershell
> # host (PowerShell) — Measured
> Get-Command apktool, apksigner | Select-Object Name, Source
> # apktool    C:\apktool\apktool.bat
> # apksigner  C:\Users\<you>\AppData\Local\Android\Sdk\build-tools\35.0.1\apksigner.bat
> ```
>
> ```bash
> # host (Git Bash) — Measured. The bare name misses; the .bat name hits.
> command -v apktool       # prints nothing, exit 1
> command -v apktool.bat   # /c/apktool/apktool.bat
> ```
>
> This is the host-toolchain form of the **vantage** problem this repository keeps meeting on
> devices — `shell` vs `app` vs `root` seeing different property sets, `su -c` vs `su 0` — and it
> fails the same way: silently, and in the direction that looks like absence.
>
> > **Mental Model**
> > A tool-availability check answers **"can this shell resolve this name"**, never **"is this tool
> > installed"**. The two answers diverge whenever a shim, an extension rule, a `PATH` difference or
> > a shell builtin sits between them — and the divergence reads as *absent*, which is the one
> > conclusion that stops you looking. Before reporting a tool missing, resolve it from a second
> > shell and look on disk. See
> > [`76-CheatSheets/scripts/vantage.sh`](../../76-CheatSheets/scripts/vantage.sh) for the
> > device-side discipline this mirrors.
>
> ### Three apktools, one `PATH`, and they are not interchangeable
>
> Read straight out of each jar's `apktool.properties` — **Measured**:
>
> | `apktool.jar` location | `application.version` | On `PATH`? |
> |---|---|---|
> | `C:\apktool\` | **3.0.1** | **yes**, via `apktool.bat` |
> | `…\APKToolGUI\Resources\` | 2.12.0 | no |
> | `C:\Program Files (x86)\apktool\Resources\` | 2.9.3 | no |
>
> 2.x and 3.x print **materially different** output for the same command — different stage names,
> different ordering, and a thread count 3.x adds and 2.x does not. So "which apktool is first on
> `PATH`" is a real variable, not trivia. Every apktool block below is 3.0.1.
>
> An earlier revision of this lab showed transcripts naming `Apktool 2.10.0` and a Linux home path,
> `/home/you/.local/share/apktool/framework/1.apk`. 2.10.0 is none of the three installed here, so
> those blocks were never a recording from this machine. They have been **replaced with measured
> 3.0.1 output**, and the one home path that survives is anonymised as `<you>`.
>
> ### Markers used below
>
> | Marker | Meaning |
> |---|---|
> | **Measured** | Produced by running the stated command on this machine. Tool versions are named; only usernames are anonymised. |
> | **Unverified** | Not executed here — either it needs a target this machine does not have, or it describes a variant of the output. Treat the exact spelling as illustrative. |
>
> ### The target the measured blocks were run against
>
> A real APK, built from scratch so you can reproduce it without pulling anything off a device:
> `aapt2 compile` + `aapt2 link` over a two-file project (a manifest declaring
> `package="com.example.target"` and one `<string>` resource), plus a `classes.dex` assembled with
> `smali.jar` from a single `RootDetector.isDeviceRooted()` method, then `zipalign -p -f 4` and
> `apksigner sign` with a key from the `keytool` command in [Step 4.2](#step-42--create-a-keystore).
> It is deliberately minimal: no `lib/`, no `assets/`, no `classes2.dex`, so the measured
> transcripts are **shorter** than a real app's. Where a production APK adds lines, that is called
> out beneath the block.
>
> ### One scripting hazard, measured
>
> `C:\apktool\apktool.bat` ends with `rem Pause when ran non interactively` followed by a `pause`
> that fires when the shim is invoked through `cmd /c`. Every measured apktool block below therefore
> ends with `Press any key to continue . . .`. **That line is the shim, not apktool**, and it will
> hang a CI job or a wrapper script. Invoke `java -jar C:\apktool\apktool.jar` directly to avoid it.
>
> **What you must install before Part 1.** `apktool` and `apksigner` reachable from the shell you
> actually use — which, per the trap above, is not the same as "installed". That is not a footnote
> you can skip: **85 of this repository's 327 lab files reference `apktool`, across 40 chapters**.
> If a command here behaves differently from what is written, the tool is right and this lab is
> wrong; fix it here.

---

## Objective

You will take a working APK apart, change how it behaves by editing its disassembled code and its
manifest, put it back together, align it, generate a signing key, sign it, verify the signature, and
install and run the result on a device. Then — the part most tutorials skip — you will look at what
your re-signing destroyed and reason about which apps that breaks and why.

This is the single most-used workflow in Android application security. Almost every practical task
sits on top of it: disabling a root check to reach the app's real functionality, turning on
debuggability so you can attach a debugger, replacing a network security configuration so your
intercepting proxy works, or adding a `System.loadLibrary` call to inject an instrumentation agent.

**You will finish able to answer:**

1. What does `apktool` actually do that plain `unzip` does not?
2. Which line of Smali makes a method return `false`, and how do I find it?
3. Why must alignment happen before signing and never after?
4. What exactly did I destroy when I re-signed, and which apps notice?
5. When is re-signing the wrong tool, and what should I use instead?

---

## Prerequisites

| Requirement | Install check | Notes |
|---|---|---|
| Java 17 or later (JDK, not just JRE) | `java -version` and `keytool -help` | apktool, apksigner and keytool are Java programs |
| `apktool` 2.9 or later; **3.0.1 is what this lab measured** | `apktool -version` from cmd/PowerShell, or `apktool.bat -version` from Git Bash | Older versions default to `aapt` instead of `aapt2` and fail on modern APKs. 2.x and 3.x print different progress output — see the note above before you diff yours against this lab's |
| Android SDK build-tools on `PATH` | `apksigner --version`, `zipalign -h`, `aapt2 version` | Measured here: `apksigner` 0.9 from build-tools 35.0.1, `aapt2` 2.19-10229193. Install "Android SDK Build-Tools" from the SDK manager or the command line tools package. On Windows `apksigner` is a `.bat` — Git Bash will not find it under the bare name |
| `adb` | `adb devices` | From platform-tools |
| A device or emulator you control | `adb devices` shows one entry | An emulator is ideal for this lab |
| An APK you are authorised to modify | — | Your own debug build, an open-source app, or a purpose-built target |
| Optional: `jadx` | `jadx --version` | Reading Java is much easier than reading Smali when locating the method |

> See [SECURITY.md](../../SECURITY.md) for authorised-testing scope.

> **Definition — Smali.** A human-readable assembly language for Dalvik bytecode, the
> instruction set stored in `classes.dex`. `apktool` converts DEX into `.smali` text files that you
> can edit and converts them back. It is not Java; it is one level below Java, comparable to reading
> x86 assembly instead of C. Chapter [12-DEX-Internals](../../12-DEX-Internals/README.md) covers
> the instruction set properly.

> **Definition — keystore.** A password-protected file holding one or more private keys and
> their certificates. Android signing uses a key from a keystore. `keytool`, shipped with the JDK,
> creates them.

---

## Setup

### Step 0.1 — Working directory and target

```bash
# host
mkdir -p ~/apk-lab-02 && cd ~/apk-lab-02
```

Pull a target from the device, or use your own build output. As in Lab 01:

```bash
# host
adb shell pm path com.example.target
adb pull /data/app/~~aBc==/com.example.target-XyZ==/base.apk target.apk
ls -l target.apk
```

### Step 0.2 — Record the "before" state

Always capture the original's identity before you change anything. You will compare against this at
the end.

```bash
# host
sha256sum target.apk | tee original.sha256
apksigner verify -v --print-certs target.apk | tee original-signature.txt
aapt2 dump badging target.apk | head -20 | tee original-badging.txt
```

Expected `original-signature.txt` shape. The **format is Measured** — it is exactly what
`apksigner` 0.9 prints, as you can see in full at [Step 4.4](#step-44--verify) — but the **values
below are illustrative placeholders**, because they describe whatever app *you* chose as a
target, which this machine has no copy of:

```
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Number of signers: 1
Signer #1 certificate DN: CN=Example Ltd, O=Example Ltd, C=GB
Signer #1 certificate SHA-256 digest: 9f3b71c4...
```

That SHA-256 digest is the app's identity as far as Android is concerned. Write it down. At the end
of this lab it will be a different number, and that difference is the whole point of Part 5.

---

## Part 1 — Decompile

### Step 1.1 — Decode with apktool

```bash
# host
apktool d -f -o work target.apk
```

Output — **Measured**, apktool 3.0.1 via `apktool.bat`, against the target described at the top of
this lab. Only the username in the framework path is anonymised:

```
I: Using Apktool 3.0.1 on target.apk with 8 threads
I: Loading resource table...
I: Baksmaling classes.dex...
I: Decoding value resources...
I: Decoding file resources...
I: Generating values XMLs...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: C:\Users\<you>\AppData\Local\apktool\framework\1.apk
I: Copying original files...
I: Copying unknown files...
Press any key to continue . . .
```

Read the **stage sequence**, not the wording — a run that stops early names the stage that failed.
Four lines there are worth pinning down now, because each one bites someone eventually:

| Line | What it actually tells you |
|---|---|
| `with 8 threads` | apktool **3.x only**. If you do not see it you are on a 2.x build, and the rest of this listing will not match: 2.x prints `Decoding file-resources...` and `Decoding values */* XMLs...` in place of the three `Decoding…`/`Generating…` lines above, and it baksmalis *after* decoding resources rather than before |
| `Loading resource table from file: …\framework\1.apk` | apktool's cached copy of the **framework** resources, extracted on first use. A wrong or missing framework is the most common decode failure on OEM builds — see Step 3.2 |
| `Copying original files...` | What populates `original/`, which is what `apktool b -c` later needs |
| `Press any key to continue . . .` | The `.bat` shim's `pause`, **not** apktool. See the scripting-hazard note at the top of this lab |

> **Unverified** — a production APK adds lines this deliberately minimal target cannot produce:
> `I: Baksmaling classes2.dex...` (and `classes3`, …) for a multidex app, and
> `I: Copying assets and libs...` when `assets/` or `lib/` are present. Their absence above is a
> property of the target, not of apktool.

### Step 1.2 — Understand what you got

```bash
# host
ls work/
```

| Path | What it is |
|---|---|
| `AndroidManifest.xml` | **Text** XML, decoded from the binary AXML. This is editable. |
| `apktool.yml` | apktool's build recipe: `versionCode`, `versionName`, `minSdkVersion`, `targetSdkVersion`, and critically the `doNotCompress` list |
| `smali/` | Disassembly of `classes.dex` |
| `smali_classes2/`, `smali_classes3/` … | Disassembly of `classes2.dex`, `classes3.dex` … |
| `res/` | Decoded resources as XML and raw files |
| `res/values/public.xml` | The name-to-resource-ID map that keeps IDs stable across a rebuild |
| `assets/` | Copied verbatim |
| `lib/` | Copied verbatim |
| `unknown/` | Entries apktool did not recognise, preserved for the rebuild |
| `original/` | The original binary `AndroidManifest.xml` and `META-INF/`, used only with `apktool b -c` |

Read `apktool.yml` now — it explains several later failures:

```bash
# host
cat work/apktool.yml
```

**Measured** — the actual `apktool.yml` written by apktool 3.0.1 for this lab's minimal target:

```yaml
version: 3.0.1
apkFileName: target.apk
usesFramework:
  ids:
  - 1
sdkInfo:
  minSdkVersion: 21
  targetSdkVersion: 35
versionInfo:
  versionCode: 1
  versionName: 1.0
resourcesInfo:
  packageId: 127
doNotCompress:
- arsc
```

**Unverified** — and here is the same file as apktool **2.x** writes it for a realistic app with
native libraries and assets. The file is not just longer, it is a *different schema*: note the
`!!brut.androlib.meta.MetaInfo` type tag, the quoted scalars, `packageInfo`/`forcedPackageId` where
3.x writes `resourcesInfo`/`packageId`, and keys (`compressionType`, `isFrameworkApk`,
`sparseResources`) that 3.x drops entirely:

```yaml
!!brut.androlib.meta.MetaInfo
apkFileName: target.apk
compressionType: false
doNotCompress:
- resources.arsc
- lib/arm64-v8a/libnative.so
- assets/model.tflite
isFrameworkApk: false
packageInfo:
  forcedPackageId: '127'
  renameManifestPackage: null
sdkInfo:
  minSdkVersion: '24'
  targetSdkVersion: '34'
sparseResources: false
usesFramework:
  ids:
  - 1
version: 2.10.0
versionInfo:
  versionCode: '1420'
  versionName: 3.14.2
```

The obvious inference from that — "so you cannot decode with one major version and rebuild with the
other" — **is wrong, and it was tested rather than assumed.** Handing the 3.0.1-decoded tree above
to the 2.9.3 jar rebuilds it cleanly, from a fresh tree, smaling included:

```
I: Using Apktool 2.9.3
I: Checking whether sources has changed...
I: Smaling smali folder into classes.dex...
I: Checking whether resources has changed...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk into: cross2.apk
```

**Measured**; the resulting APK carries the same three entries, `classes.dex` among them. 2.x
ignores the keys it does not recognise and falls back to defaults for the ones it wants and cannot
find. So mixing versions is *tolerated*, not *guaranteed* — the failure mode when it does bite is a
silently different rebuild rather than an error, which is the worst kind. Decode and rebuild with
the same binary when you can, and if you cannot, diff the entry list against the original before
you trust the result.

> **Under the Hood** `doNotCompress` is not a cosmetic setting. `resources.arsc` must be STORED
> (uncompressed) and 4-byte aligned for apps targeting API 30 and above, because the framework
> memory-maps it. Native libraries must be STORED and page-aligned when
> `android:extractNativeLibs="false"`, because the dynamic linker maps them straight out of the
> APK. If you delete these lines, your rebuild will either fail to install or crash on first
> resource access.

### Step 1.3 — Get readable Java to find your target code

Smali is precise but hostile to read. Use `jadx` to locate the method, then edit the Smali.

```bash
# host
jadx -d jadx-out --show-bad-code target.apk 2>/dev/null
grep -rn "isRooted\|isDeviceRooted\|checkRoot\|detectRoot\|su\b" jadx-out/sources/ | head -20
```

Expected finding shape:

```
jadx-out/sources/com/example/target/security/RootDetector.java:31:    public static boolean isDeviceRooted() {
jadx-out/sources/com/example/target/security/RootDetector.java:44:        if (checkSuBinary()) {
jadx-out/sources/com/example/target/MainActivity.java:88:        if (RootDetector.isDeviceRooted()) {
```

Open the Java to confirm the semantics before you touch anything:

```java
// jadx output — com/example/target/security/RootDetector.java
public static boolean isDeviceRooted() {
    return checkSuBinary() || checkTestKeys() || checkMagiskPaths();
}
```

You want `isDeviceRooted()` to return `false` unconditionally.

---

## Part 2 — Modify

You will make three independent changes. Each one is useful on its own; doing all three teaches
different failure modes.

### Change A — Force a boolean method to return `false` (Smali)

#### Step 2.1 — Find the Smali

```bash
# host
grep -rln "isDeviceRooted" work/smali*/
```

```
work/smali/com/example/target/security/RootDetector.smali
```

```bash
# host
grep -n -A 20 "\.method public static isDeviceRooted" \
  work/smali/com/example/target/security/RootDetector.smali
```

Expected:

```smali
.method public static isDeviceRooted()Z
    .locals 1

    invoke-static {}, Lcom/example/target/security/RootDetector;->checkSuBinary()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    invoke-static {}, Lcom/example/target/security/RootDetector;->checkTestKeys()Z

    move-result v0

    ...
.end method
```

#### Step 2.2 — Understand the three lines that matter

| Smali | Meaning |
|---|---|
| `.method public static isDeviceRooted()Z` | Method declaration. The trailing `Z` is the return type: `Z` is `boolean`, `I` is `int`, `V` is `void`, `Ljava/lang/String;` is a String. |
| `.locals 1` | This method uses 1 local register, named `v0`. If you need more registers than declared, the app crashes at verification. |
| `const/4 v0, 0x0` | Put the 4-bit constant 0 into register `v0`. For a boolean, 0 is `false` and 1 is `true`. |
| `return v0` | Return the value in `v0`. |

The patch is therefore two instructions inserted immediately after `.locals`, which makes every
instruction after them unreachable.

#### Step 2.3 — Apply the patch

Edit `work/smali/com/example/target/security/RootDetector.smali` so the method begins like this:

```smali
.method public static isDeviceRooted()Z
    .locals 1

    const/4 v0, 0x0

    return v0

    invoke-static {}, Lcom/example/target/security/RootDetector;->checkSuBinary()Z
    ...
.end method
```

> **Warning** Do **not** delete the rest of the method body. Smali labels (`:cond_0`) and
> try/catch directives (`.catch`) reference each other; removing lines piecemeal produces
> assembler errors that are tedious to debug. Leaving dead code after an unconditional `return` is
> perfectly legal and assembles cleanly.

> **Warning** Do not lower `.locals`. If the original said `.locals 4` and you only use `v0`,
> leave it at 4. Raising it is safe; lowering it is not.

Common variants you will meet:

| Original method returns | Patch to insert after `.locals N` |
|---|---|
| `Z` (boolean) — force `false` | `const/4 v0, 0x0` then `return v0` |
| `Z` (boolean) — force `true` | `const/4 v0, 0x1` then `return v0` |
| `I` (int) — force 0 | `const/4 v0, 0x0` then `return v0` |
| `I` (int) — force a large value | `const v0, 0x7fffffff` then `return v0` |
| `V` (void) — make it a no-op | `return-void` |
| `Ljava/lang/String;` — force null | `const/4 v0, 0x0` then `return-object v0` |
| `Ljava/lang/String;` — force a literal | `const-string v0, "patched"` then `return-object v0` |

If `.locals 0` is declared and you need a register, change it to `.locals 1` — that is the one
direction it is safe to move.

### Change B — Make the app debuggable (manifest)

#### Step 2.4 — Edit the manifest

```bash
# host
head -8 work/AndroidManifest.xml
```

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:compileSdkVersion="34"
    android:versionCode="1420"
    android:versionName="3.14.2"
    package="com.example.target">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
    <application android:name="com.example.target.App" android:allowBackup="false" ...>
```

Add `android:debuggable="true"` to the `<application>` element:

```xml
<application
    android:name="com.example.target.App"
    android:allowBackup="false"
    android:debuggable="true"
    ... >
```

> **Pentester's Note** `android:debuggable="true"` is the highest-value single-attribute
> change in Android testing. It lets you attach a JDWP debugger, use `run-as` to read the app's
> private data directory, and makes Frida attachment simpler on non-rooted devices. It is also the
> attribute that anti-tamper code checks most often, via
> `ApplicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE`. Chapter
> [38-TamperDetection](../../38-TamperDetection/README.md) covers detecting and defeating that.

### Change C — Replace the network security configuration

Modern apps declare a network security configuration that pins certificates or forbids user-added
certificate authorities, which blocks an intercepting proxy.

#### Step 2.5 — Find the current configuration

```bash
# host
grep -o 'networkSecurityConfig="[^"]*"' work/AndroidManifest.xml
cat work/res/xml/network_security_config.xml
```

Expected original:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">k3Xk...=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

#### Step 2.6 — Replace it with a permissive one

```bash
# host
cat > work/res/xml/network_security_config.xml <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>
XML
```

Removing the `<pin-set>` disables certificate pinning declared through the platform mechanism. It
does **not** disable pinning implemented in code (OkHttp `CertificatePinner`, a custom
`TrustManager`, or a native check) — that is chapter
[36-CertificatePinning](../../36-CertificatePinning/README.md).

If the manifest does not reference a config at all, add one:

```xml
<application ... android:networkSecurityConfig="@xml/network_security_config">
```

and create the file at `work/res/xml/network_security_config.xml` as above.

---

## Part 3 — Rebuild

### Step 3.1 — Build

```bash
# host
apktool b work -o rebuilt.apk
```

Output — **Measured**, apktool 3.0.1, rebuilding the tree decoded in Step 1.1:

```
I: Using Apktool 3.0.1 on target.apk with 8 threads
I: Smaling smali folder into classes.dex...
I: Building resources with aapt2...
I: Building apk file...
I: Built apk into: rebuilt.apk
Press any key to continue . . .
```

`on target.apk` names the **original** APK, read back out of `apktool.yml` — it is not the name of
what you are producing. `-o rebuilt.apk` decides that, and the last line confirms it.

> **Unverified** — on a larger project this run also prints
> `I: Smaling smali_classes2 folder into classes2.dex...` per extra dex,
> `I: Copying libs... (/lib)`, and `I: Copying unknown files/dir...`. apktool 2.x additionally
> prints `I: Checking whether sources has changed...` and
> `I: Checking whether resources has changed...`, which 3.0.1 does not; if you are diffing this
> lab against your own output, check your version first.

### Step 3.2 — If it fails, read the error carefully

| Error | Cause | Fix |
|---|---|---|
| `aapt2 exited with code 1` followed by an XML error | Your manifest or resource edit is malformed | Read the line number aapt2 printed; fix the XML |
| `Could not find framework resource` | Vendor/OEM resources needed | `apktool if /path/to/framework-res.apk` (pull it from the device with `adb pull /system/framework/framework-res.apk`) |
| `Error occurred while disassembling class` (at decode time) | Obfuscated or non-standard DEX | Retry with `apktool d -s` to keep DEX raw, and patch the DEX with `baksmali`/`smali` directly |
| `invalid resource directory name` | You created a `res/` folder with a bad qualifier | Match an existing folder's naming convention exactly |
| `java.lang.OutOfMemoryError` | Large APK | Run with a bigger heap: `java -Xmx4g -jar apktool.jar b work -o rebuilt.apk` |
| `Multiple resources with name` | Duplicate resource declaration after an edit | Remove the duplicate from `res/values/` |
| Smali assembler error `Verification error` / `mismatched input` | Bad register count, mistyped opcode, or an orphaned label | Re-check `.locals` and the exact opcode spelling |

### Step 3.3 — Confirm the rebuild actually contains your change

Never trust that an edit made it in. Check.

```bash
# host — the manifest change
aapt2 dump xmltree rebuilt.apk --file AndroidManifest.xml | grep -i debuggable
```

Expected:

```
      A: http://schemas.android.com/apk/res/android:debuggable(0x0101000f)=(type 0x12)0xffffffff
```

`type 0x12` is `TYPE_INT_BOOLEAN` and `0xffffffff` is `true` — exactly the encoding from the
`Res_value` table in the chapter [cheat sheet](../cheatsheet.md).

```bash
# host — the network security config change
aapt2 dump xmltree rebuilt.apk --file res/xml/network_security_config.xml
```

```bash
# host — the code change: re-decode and diff
apktool d -f -o verify rebuilt.apk >/dev/null 2>&1
grep -n -A 6 "\.method public static isDeviceRooted" \
  verify/smali/com/example/target/security/RootDetector.smali
```

### Step 3.4 — Note what the rebuild has already destroyed

```bash
# host
apksigner verify -v rebuilt.apk
```

Output — **Measured**, `apksigner` 0.9 from build-tools 35.0.1, on the APK apktool had just
rebuilt. Note how short the real diagnosis is:

```
DOES NOT VERIFY
ERROR: Missing META-INF/MANIFEST.MF
```

`apksigner` does not reach the v2 block at all: with no `META-INF/MANIFEST.MF` there is no v1
signature to check, and the v2 signature that *was* in the original is gone with the bytes it
covered. There is nothing left to disagree about.

apktool does not carry the signature forward and could not do so even if it wanted to: every byte
of the archive changed. This is normal. Continue.

---

## Part 4 — Align, key, sign, verify, install

### Step 4.1 — Align

```bash
# host
zipalign -p -f -v 4 rebuilt.apk aligned.apk | tail -5
```

For a device with 16 KB memory pages (Android 15 and later on supported hardware):

```bash
# host
zipalign -p -f -P 16 -v 4 rebuilt.apk aligned.apk | tail -5
```

| Flag | Meaning |
|---|---|
| `4` | Align uncompressed entries to a 4-byte boundary |
| `-p` | Additionally page-align `.so` entries |
| `-P 16` | Use a 16 KB page size for `.so` alignment |
| `-f` | Overwrite the output if it exists |
| `-v` | Verbose per-entry report |
| `-c` | Check only, change nothing |

Confirm:

```bash
# host
zipalign -c -v 4 aligned.apk | tail -3
echo "exit code: $?"        # 0 means aligned
```

> **Warning — order of operations.** Align first, sign second. `apksigner` preserves existing
> alignment when it inserts the signing block. `zipalign` does *not* preserve signatures: it moves
> entry data, which changes the v2/v3 digests and produces
> `INSTALL_PARSE_FAILED_NO_CERTIFICATES` at install time. If you only remember one rule from this
> lab, make it this one.

### Step 4.2 — Create a keystore

```bash
# host
keytool -genkeypair -v \
  -keystore lab.keystore \
  -alias labkey \
  -keyalg RSA -keysize 2048 \
  -validity 10000 \
  -storepass androidlab -keypass androidlab \
  -dname "CN=APK Lab, OU=Research, O=Android Pentesting Notes, L=NA, ST=NA, C=NA"
```

Expected:

```
Generating 2,048 bit RSA key pair and self-signed certificate (SHA384withRSA) with a validity of 10,000 days
	for: CN=APK Lab, OU=Research, O=Android Pentesting Notes, L=NA, ST=NA, C=NA
[Storing lab.keystore]
```

```bash
# host — look at what you just made
keytool -list -v -keystore lab.keystore -storepass androidlab | head -20
```

> **Warning** `androidlab` is a lab password written in a public document. This keystore is for
> testing on devices you control and nothing else. A real signing key protects the identity of an
> application to every user who has ever installed it: losing it means you can never update the app
> again, and leaking it means anyone can publish an "update" that Android will happily accept.
> Real keys belong in an HSM or a Play App Signing arrangement, not in a repository.

> **Under the Hood** The certificate `keytool` generates is self-signed. Android does not build
> or validate a chain to a trust anchor for app signing — there is no certificate authority for
> APKs. The only property Android enforces is *continuity*: an update must be signed by the same
> key as the installed version, or by a key that the installed key delegated to through a v3
> rotation lineage. The certificate's fields are metadata, not trust.

### Step 4.3 — Sign

```bash
# host
apksigner sign \
  --ks lab.keystore \
  --ks-key-alias labkey \
  --ks-pass pass:androidlab \
  --key-pass pass:androidlab \
  --min-sdk-version 24 \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --v4-signing-enabled false \
  --out final.apk \
  aligned.apk
```

`apksigner sign` prints nothing on success. Choose the scheme flags deliberately:

| Situation | Flags |
|---|---|
| Target device is API 24+ (almost always) | `--v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true` |
| Target device is API 23 or older | `--v1-signing-enabled true` is mandatory |
| You want `adb install --incremental` | Add `--v4-signing-enabled true`; produces `final.apk.idsig` |
| App targets API 30+ | v2 or higher is **required** by the installer |

Leaving v1 enabled costs nothing but adds `META-INF/` entries; leaving it *off* on a device below
API 24 makes the APK uninstallable.

### Step 4.4 — Verify

```bash
# host
apksigner verify -v --print-certs final.apk
```

Output — **Measured**, `apksigner` 0.9 from build-tools 35.0.1, on an APK signed with a key from
the exact `keytool` command in Step 4.2. This is the whole block, unedited:

```
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1
Signer #1 certificate DN: CN=APK Lab, OU=Research, O=Android Pentesting Notes, L=NA, ST=NA, C=NA
Signer #1 certificate SHA-256 digest: 8cf434b679466ffaf6604dda0962588df47edf3570611c6fb0d96081e698d9d9
Signer #1 certificate SHA-1 digest: 8a5c663daf52ab31ad8bc10551ca916563aa137e
Signer #1 certificate MD5 digest: 3ec50a68607191e834f586893d7eafad
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #1 public key SHA-256 digest: 61f629c26d5160ea225c3de4ee26efb436e3250c2e1112c7e91272b24d824ac8
Signer #1 public key SHA-1 digest: 866c67a786d906c1ce3f94c09dafe07a85c6a651
Signer #1 public key MD5 digest: 3b09d121a8f622cc0fe5f793646347dd
```

Two things to take from it. **The DN will match yours exactly**, because it comes from the `-dname`
you passed in Step 4.2 — a DN is a claim, not an identity, and anyone can type that string.
**Every digest will differ**, because `keytool -genkeypair` generated a fresh RSA key; the digest
is of *your* certificate. That contrast is the lesson: the human-readable field is forgeable, the
digest is the identity. v3.1 and v4 read `false` because neither is produced by default: v4 needs
`--v4-signing-enabled` and emits a separate `.idsig` file beside the APK, and v3.1 only appears
when you are actually rotating, via `--lineage` with `--rotation-min-sdk-version`. A single-key
signing run has nothing to put in either. (Flag names checked against this `apksigner`'s own
`sign --help`.)

Compare that SHA-256 digest with `original-signature.txt`. They are different, and they will stay
different. Part 5 is about the consequences.

### Step 4.5 — Install and run

```bash
# host — the old app is signed by a different key, so it must go first
adb uninstall com.example.target
adb install -r final.apk
```

Expected:

```
Performing Streamed Install
Success
```

```bash
# host — launch and watch
adb shell monkey -p com.example.target -c android.intent.category.LAUNCHER 1
adb logcat -c && adb logcat | grep -i "com.example.target"
```

### Step 4.6 — Confirm the behavioural change

```bash
# adb shell — debuggable? Look for the DEBUGGABLE flag
adb shell dumpsys package com.example.target | grep -i flags
```

Expected to contain `DEBUGGABLE`:

```
    flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ]
```

```bash
# host — run-as only works on debuggable apps; this is the practical proof
adb shell run-as com.example.target ls -la /data/data/com.example.target/
```

For the root check, launch the app on a rooted device or emulator that previously refused to start
and confirm it now proceeds past the root screen. For the network configuration, install your proxy
CA as a user certificate and confirm traffic to a previously pinned domain now decodes.

---

## Part 5 — What you just destroyed

The rebuilt app runs, but it is not the same application any more. Three things changed and each has
consequences you must be able to explain to a client.

### 5.1 — The original v2/v3 signature is gone, permanently

The original APK's v2 and v3 signatures were computed over the whole file with the developer's
private key. You do not have that key. Any change to any byte invalidates those digests, and you
cannot recompute them. The signing block you produced contains *your* signature over *your* bytes.

That is not a limitation of your tooling; it is the security property working. If you could preserve
a signature across a modification, APK signing would be useless.

### 5.2 — Apps that check their own signature will notice

An application can ask the platform who signed it and compare the answer to a value baked into its
own code. After re-signing, the answer changes.

```java
// Android app code — the typical check, API 28+
PackageInfo info = getPackageManager().getPackageInfo(
        getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
for (Signature sig : info.getSigningInfo().getApkContentsSigners()) {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(sig.toByteArray());
    if (!Arrays.equals(digest, EXPECTED_DIGEST)) {
        throw new SecurityException("tampered");
    }
}
```

```java
// Android app code — the lineage-aware form a well-written app uses instead
boolean ok = getPackageManager().hasSigningCertificate(
        getPackageName(), EXPECTED_SHA256, PackageManager.CERT_INPUT_SHA256);
```

Find these in your target:

```bash
# host
grep -rn "GET_SIGNING_CERTIFICATES\|GET_SIGNATURES\|getApkContentsSigners\|hasSigningCertificate\|checkSignatures" \
  jadx-out/sources/ | head -20
grep -rn "signingInfo\|getPackageInfo" work/smali*/ | grep -i sign | head -20
```

The native variant is the one people miss. If the app links a `.so`, the check may be implemented
in C++ calling back into JNI, or reading the APK file directly and parsing it in native code:

```bash
# host
for so in $(find work/lib -name '*.so'); do
  echo "== $so"
  strings -a "$so" | grep -iE 'getPackageInfo|signatures|GET_SIGNING|/data/app|base\.apk' | head
done
```

Chapter [38-TamperDetection](../../38-TamperDetection/README.md) covers the full taxonomy;
`../scripts/apk-signature-hooks.js` in this chapter observes and optionally spoofs the Java-side
paths at runtime.

### 5.3 — Server-side and platform bindings break

| Binding | What breaks |
|---|---|
| Play Integrity API / attestation | The server sees a different certificate digest and an unrecognised package integrity verdict |
| Firebase App Check | Rejects the app |
| Google Maps / Firebase API keys restricted to a SHA-1 fingerprint | Requests are refused |
| App Links verified through `assetlinks.json` | The domain no longer claims this app; links open in the browser |
| `android:sharedUserId` with a companion app | The two apps no longer share a UID |
| Signature-level permissions between your app and another | No longer granted |
| Backup/restore of the original app's data | Refused: different signer |

### 5.4 — When to *not* re-sign

Re-signing is the right tool for static, offline analysis and for making an app cooperate with your
debugger. It is the wrong tool whenever the thing you want to observe depends on the app's real
identity — anything involving the app's backend, attestation, or a companion app.

The alternative is runtime instrumentation of the *unmodified* APK, which leaves the signature
intact:

```bash
# host — spawn the original, unmodified app with instrumentation attached
frida -U -f com.example.target -l ../scripts/apk-signature-hooks.js
```

```bash
# host — or use Objection's built-in helpers
objection -g com.example.target explore
```

See [53-Frida](../../53-Frida/README.md) and [54-Objection](../../54-Objection/README.md). A useful
rule: *patch to understand, hook to observe*.

---

## Part 6 — Cleanup and reproducibility

```bash
# host — leave a record of what you did
cat > BUILD-NOTES.md <<'EOF'
# Rebuild record
Original SHA-256      : (see original.sha256)
Original signer digest: (see original-signature.txt)
Changes:
  1. RootDetector.isDeviceRooted() forced to return false (smali)
  2. android:debuggable="true" added to <application>
  3. res/xml/network_security_config.xml replaced with a permissive config
Rebuilt with          : apktool b -> zipalign -p -f 4 -> apksigner sign (v1+v2+v3)
New signer digest     : (see below)
EOF
apksigner verify -v --print-certs final.apk >> BUILD-NOTES.md
sha256sum final.apk >> BUILD-NOTES.md
```

```bash
# host — restore the device to its original state when finished
adb uninstall com.example.target
adb install -r target.apk       # only works if the original signer's APK is what you pulled
```

---

## Hints

<details>
<summary>Hint 1 — apktool rebuild fails and I cannot read the error</summary>

Run with verbose output; the real error is usually several lines above the `AndrolibException`:

```bash
apktool -v b work -o rebuilt.apk 2>&1 | tail -40
```

If it mentions `aapt2`, the problem is in a resource or the manifest, not in your Smali. aapt2
prints a `file:line:column` reference — go there.
</details>

<details>
<summary>Hint 2 — the app installs but crashes immediately with a VerifyError</summary>

Your Smali patch is inconsistent with the declared register count or the method signature. Check:

- `.locals N` is at least as large as the highest `vN` register you use.
- The `return` opcode matches the return type: `return` for `Z`/`I`, `return-object` for object
  types, `return-void` for `V`, `return-wide` for `J`/`D`.
- You did not delete a label that a `goto` or `if-*` still targets.

```bash
adb logcat | grep -iE "VerifyError|rejecting|Failure to verify"
```
</details>

<details>
<summary>Hint 3 — INSTALL_PARSE_FAILED_NO_CERTIFICATES even though apksigner says it verifies</summary>

You aligned after signing. Redo the pipeline in the correct order:

```bash
zipalign -p -f 4 rebuilt.apk aligned.apk
apksigner sign --ks lab.keystore --ks-key-alias labkey --ks-pass pass:androidlab \
  --key-pass pass:androidlab --out final.apk aligned.apk
```

Also check that no leftover `META-INF/*.SF` or `*.RSA` from the original survived into `work/` —
delete them before rebuilding if they did.
</details>

<details>
<summary>Hint 4 — INSTALL_FAILED_UPDATE_INCOMPATIBLE</summary>

The device still has the original app, signed by the developer's key. Android will never let a
different signer replace it, and there is no flag that overrides this. Uninstall first:

```bash
adb uninstall com.example.target
```

If uninstalling would lose data you need, back it up first with `adb backup` (for apps that allow
it) or `run-as` on a debuggable build, or change the `package` attribute so your build installs
alongside the original —renaming the package requires updating every fully-qualified
reference, which `apktool`'s `--rename-manifest-package` handles only partially.
</details>

<details>
<summary>Hint 5 — the app starts, but the root screen still appears</summary>

You patched one of several checks. Applications commonly implement three or four independently.
Search wider, and remember the native side:

```bash
grep -rn "su\"\|/system/bin/su\|magisk\|Superuser\|test-keys\|ro.debuggable" jadx-out/sources/ | head -30
find work/lib -name '*.so' -exec strings -a {} \; | grep -iE 'magisk|/system/bin/su|test-keys' | sort -u
```

Rather than patching each one, hook them all at runtime — see
[37-RootDetection](../../37-RootDetection/README.md).
</details>

<details>
<summary>Hint 6 — resources are missing or wrong after the rebuild</summary>

Two usual causes. Either `res/values/public.xml` was modified or deleted, so resource IDs were
reassigned and the compiled code now references the wrong ones; restore it from a fresh
`apktool d`. Or `resources.arsc` was compressed because `doNotCompress` in `apktool.yml` lost its
entry; check with:

```bash
unzip -v final.apk | grep -E 'resources\.arsc|\.so$'
```

The Method column must read `Stored` for `resources.arsc` and for `.so` files when
`extractNativeLibs="false"`.
</details>

---

## Success criteria

| # | Criterion | Proof |
|---|---|---|
| 1 | You decoded the APK and can explain each top-level output | You can say what `apktool.yml`, `public.xml`, `unknown/` and `original/` are for |
| 2 | You made a Smali change that alters behaviour | `grep -A6 isDeviceRooted` on a re-decode of your build shows `const/4 v0, 0x0` then `return v0` |
| 3 | You made a manifest change | `aapt2 dump xmltree final.apk --file AndroidManifest.xml \| grep debuggable` shows `(type 0x12)0xffffffff` |
| 4 | You replaced the network security configuration | `aapt2 dump xmltree final.apk --file res/xml/network_security_config.xml` shows `user` trust anchors |
| 5 | The build is aligned | `zipalign -c -v 4 final.apk` exits 0 |
| 6 | The build is signed and verifies | `apksigner verify -v final.apk` prints `Verifies` with v2 and v3 `true` |
| 7 | The build installs and runs | `adb install -r final.apk` prints `Success`, and the app launches |
| 8 | The behavioural change is observable on the device | `adb shell run-as com.example.target ls` works, and the root screen no longer blocks you |
| 9 | You can explain what re-signing broke | You can list at least four things from Part 5 without looking |
| 10 | You know when not to do this | You can state the case for hooking the original APK instead |

---

## Where to go next

[Lab 03 — Write Your Own AXML Parser](lab-03-write-your-own-axml-parser.md) takes you inside the
binary manifest you have been editing through `apktool`, and builds the reading you will need next.
[Lab 04 — CTF: The Lying Manifest](lab-04-ctf-the-lying-manifest.md) then combines the container
knowledge from Lab 01 with the tooling from this lab into a CTF challenge where your tools and the
platform disagree about what the APK contains.

For the wider topics this lab touched: [12-DEX-Internals](../../12-DEX-Internals/README.md) for the
Smali instruction set, [32-Manifest](../../32-Manifest/README.md) for manifest attribute semantics,
[36-CertificatePinning](../../36-CertificatePinning/README.md) for pinning implemented in code,
[37-RootDetection](../../37-RootDetection/README.md) for the checks you patched, and
[38-TamperDetection](../../38-TamperDetection/README.md) for the signature checks you broke.
