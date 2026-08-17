<!-- GENERATED FILE. Do not edit by hand.
     Rebuild with:  python3 -B scripts/build-cheatsheet-index.py --by task
     Source: the `cheatsheet.md` of every chapter in this repository. -->

# Cheat-sheet router — by task

Built mechanically by [`build-cheatsheet-index.py`](../scripts/build-cheatsheet-index.py)
from every chapter's `cheatsheet.md`. It **routes**; it does not copy. An entry
separated from the chapter that justifies it is how a reader ends up pasting a
command they cannot defend — see [`../README.md`](../README.md) section 7.

Organised by **what you are doing**, not by chapter number. This is the grouping
a per-chapter sheet cannot provide, because no single chapter owns a task.


| Task | Sheets | Sections in scope |
|---|---:|---:|
| [I have an APK and one hour](#i-have-an-apk-and-one-hour) | 10 | 156 |
| [I am on an unrooted device](#i-am-on-an-unrooted-device) | 10 | 158 |
| [I have only an emulator](#i-have-only-an-emulator) | 9 | 140 |
| [The app detects my hook](#the-app-detects-my-hook) | 10 | 146 |
| [I need to see the traffic](#i-need-to-see-the-traffic) | 9 | 132 |
| [I need to read the app's data](#i-need-to-read-the-apps-data) | 8 | 129 |
| [I need to reach it from another app](#i-need-to-reach-it-from-another-app) | 10 | 152 |
| [I am staring at native code](#i-am-staring-at-native-code) | 10 | 162 |
| [I need to prove this finding](#i-need-to-prove-this-finding) | 6 | 92 |
| [Nothing works and I do not know why](#nothing-works-and-i-do-not-know-why) | 7 | 107 |

---

## I have an APK and one hour

Triage order, not depth order. Manifest before code, code before runtime, and every automated hit adjudicated by hand before it is written down.

| Sheet | Sections | Read it for |
|---|---:|---|
| [10 — APK Internals](../../10-APK-Internals/cheatsheet.md) | 26 | 1. ZIP record signatures (all little-endian on disk); 2. Local File Header — field offsets (30 bytes fixed + variable); 3. Central Directory File Header — field offsets (46 bytes fixed + variable); 4. General Purpose Bit Flag; … |
| [32 — Manifest](../../32-Manifest/cheatsheet.md) | 16 | Read it three ways — always; THE FIRST THING TO CHECK: targetSdkVersion; `<manifest>`; `<application>` — the highest-yield element; … |
| [52 — StaticAnalysis](../../52-StaticAnalysis/cheatsheet.md) | 13 | The pipeline; Five-minute pass; The grep catalogue; The triage decision table; … |
| [56 — JADX](../../56-JADX/cheatsheet.md) | 13 | Invocation; The ten-command first pass; Flags; Input formats; … |
| [55 — MobSF](../../55-MobSF/cheatsheet.md) | 11 | 1. Install, run, authenticate; 2. REST API; 3. Finding categories — what it detected, and how to confirm; 4. Classify a "secret" before you name it; … |
| [44 — NetworkSecurityConfig](../../44-NetworkSecurityConfig/cheatsheet.md) | 16 | 1. The complete schema; 2. Every element and attribute; 3. `src` values; 4. Version matrix; … |
| [23 — Permissions](../../23-Permissions/cheatsheet.md) | 18 | 1. The three lists — and the fourth; 2. `protectionLevel` — base levels; 3. `protectionLevel` — flags; 4. Permission → GID map (`platform.xml`) **M**; … |
| [40 — Obfuscation](../../40-Obfuscation/cheatsheet.md) | 13 | Triage — is it protected, and how?; DEX header offsets; Extraction; Static grep table; … |
| [33 — Storage](../../33-Storage/cheatsheet.md) | 12 | Storage roots for one package; Subdirectories of the CE/DE tree; Availability by device state; Reachability: three gates, all must agree; … |
| [46 — Tokens](../../46-Tokens/cheatsheet.md) | 18 | 1. Identify the token in one glance; 2. JOSE header members; 3. Registered claims (RFC 7519 §4.1); 3a. OIDC claims; … |

## I am on an unrooted device

Everything here works at uid 2000 or below. Repackaging with the Frida Gadget, `run-as` on a debuggable build, and instrumentation gated by the signing key rather than by root.

| Sheet | Sections | Read it for |
|---|---:|---|
| [09 — Android App Internals](../../09-Android-App-Internals/cheatsheet.md) | 17 | 1. Identity — package, UID, appId, userId; 2. Package / UID inspection commands; 3. `/data/system/packages.list`; 4. `/data/system/packages.xml`; … |
| [10 — APK Internals](../../10-APK-Internals/cheatsheet.md) | 26 | 1. ZIP record signatures (all little-endian on disk); 2. Local File Header — field offsets (30 bytes fixed + variable); 3. Central Directory File Header — field offsets (46 bytes fixed + variable); 4. General Purpose Bit Flag; … |
| [51 — DynamicAnalysis](../../51-DynamicAnalysis/cheatsheet.md) | 14 | The pipeline; Device posture — 40 seconds, run it first; The nine channels; Altitudes — pick the lowest that works; … |
| [53 — Frida](../../53-Frida/cheatsheet.md) | 12 | The four commands that start every session; Setup; CLI; Java API; … |
| [54 — Objection](../../54-Objection/cheatsheet.md) | 16 | 1. CLI; 2. Session hygiene — the four commands that prevent most problems; 3. Generic REPL commands; 4. `android hooking` — reconnaissance; … |
| [60 — ADB](../../60-ADB/cheatsheet.md) | 17 | The 24-byte message header; Message types; Stream rules; Service strings (the `A_OPEN` payload); … |
| [66 — Instrumentation](../../66-Instrumentation/cheatsheet.md) | 17 | The gate — measured matrix **[M]**; Startup ordering **[M]**; Identity inside the process **[M]**; Vantage: shell vs instrumented app **[M]**; … |
| [36 — CertificatePinning](../../36-CertificatePinning/cheatsheet.md) | 12 | The pin; Compute it; Generate a backup key; The layers; … |
| [43 — WebView](../../43-WebView/cheatsheet.md) | 11 | 1. WebSettings defaults by targetSdkVersion — the table **(M)**; 2. Severity, honestly; 3. Commands; 4. Static analysis; … |
| [44 — NetworkSecurityConfig](../../44-NetworkSecurityConfig/cheatsheet.md) | 16 | 1. The complete schema; 2. Every element and attribute; 3. `src` values; 4. Version matrix; … |

## I have only an emulator

What an AVD can and cannot answer. Attestation, verified boot and fastboot are the three questions it answers wrongly rather than not at all.

| Sheet | Sections | Read it for |
|---|---:|---|
| [39 — EmulatorDetection](../../39-EmulatorDetection/cheatsheet.md) | 14 | Grades; The full signal table; The nine DEAD checks — memorise these; The inverted checks — these get it backwards; … |
| [49 — KeyStore](../../49-KeyStore/cheatsheet.md) | 12 | The one sentence; The stack; `KeyGenParameterSpec` — the options that decide severity; `KeyInfo` — what you actually got; … |
| [50 — HardwareBackedSecurity](../../50-HardwareBackedSecurity/cheatsheet.md) | 11 | 1. The security-level capability matrix; 2. Determine each capability on a device; 3. The scripts; 4. Measured results (record the device with every number); … |
| [61 — Fastboot](../../61-Fastboot/cheatsheet.md) | 20 | Risk key; Getting in and out; Reads — the whole safe surface; `getvar` variables; … |
| [62 — Magisk](../../62-Magisk/cheatsheet.md) | 14 | Install / flash; Which partition do I patch?; Verify installation; Filesystem layout; … |
| [35 — SSL](../../35-SSL/cheatsheet.md) | 18 | The five commands that matter; Version matrix — where the trust anchors live; Trust-anchor rule by targetSdk; Platform trust-manager delegation **[M]**; … |
| [44 — NetworkSecurityConfig](../../44-NetworkSecurityConfig/cheatsheet.md) | 16 | 1. The complete schema; 2. Every element and attribute; 3. `src` values; 4. Version matrix; … |
| [13 — ART](../../13-ART/cheatsheet.md) | 19 | The one command that matters; Artifacts on disk; Compiler filters; Commands; … |
| [21 — App Sandbox](../../21-App-Sandbox/cheatsheet.md) | 16 | The one paragraph; UID arithmetic; Network GIDs (`platform.xml` → supplementary groups); Reading a process's sandbox; … |

## The app detects my hook

Find the check before you bypass it. A bypass applied to the wrong seam reads exactly like a bypass that failed.

| Sheet | Sections | Read it for |
|---|---:|---|
| [37 — RootDetection](../../37-RootDetection/cheatsheet.md) | 17 | The one-line summary; Triage — is there root detection, and what kind?; Verdict table; Artefact reference; … |
| [38 — TamperDetection](../../38-TamperDetection/cheatsheet.md) | 15 | 1. THE CATALOGUE — what each check proves, and what it costs to defeat; 2. THE THREE THREATS — do not conflate them; 3. THE API; 4. VERSION MATRIX; … |
| [39 — EmulatorDetection](../../39-EmulatorDetection/cheatsheet.md) | 14 | Grades; The full signal table; The nine DEAD checks — memorise these; The inverted checks — these get it backwards; … |
| [40 — Obfuscation](../../40-Obfuscation/cheatsheet.md) | 13 | Triage — is it protected, and how?; DEX header offsets; Extraction; Static grep table; … |
| [53 — Frida](../../53-Frida/cheatsheet.md) | 12 | The four commands that start every session; Setup; CLI; Java API; … |
| [62 — Magisk](../../62-Magisk/cheatsheet.md) | 14 | Install / flash; Which partition do I patch?; Verify installation; Filesystem layout; … |
| [63 — LSPosed](../../63-LSPosed/cheatsheet.md) | 18 | The four layers; Framework comparison; Module anatomy; Entry points; … |
| [64 — Xposed](../../64-Xposed/cheatsheet.md) | 15 | The one-paragraph summary; Timeline; Version matrix; What a classic install wrote [D, probed [M]]; … |
| [65 — Hooking](../../65-Hooking/cheatsheet.md) | 15 | 1. The five hook types; 2. Verified AArch64 encodings; 3. The three patch forms; 4. Branch and address-formation reach; … |
| [67 — BypassingProtections](../../67-BypassingProtections/cheatsheet.md) | 13 | The five seams; Seam / altitude table — cost and detectability; Symptom → cause → first move; `ApplicationExitInfo` decoder (API 30+); … |

## I need to see the traffic

Trust store, then config, then pinning, then non-HTTP. Stop at the first layer that explains the silence.

| Sheet | Sections | Read it for |
|---|---:|---|
| [35 — SSL](../../35-SSL/cheatsheet.md) | 18 | The five commands that matter; Version matrix — where the trust anchors live; Trust-anchor rule by targetSdk; Platform trust-manager delegation **[M]**; … |
| [36 — CertificatePinning](../../36-CertificatePinning/cheatsheet.md) | 12 | The pin; Compute it; Generate a backup key; The layers; … |
| [43 — WebView](../../43-WebView/cheatsheet.md) | 11 | 1. WebSettings defaults by targetSdkVersion — the table **(M)**; 2. Severity, honestly; 3. Commands; 4. Static analysis; … |
| [44 — NetworkSecurityConfig](../../44-NetworkSecurityConfig/cheatsheet.md) | 16 | 1. The complete schema; 2. Every element and attribute; 3. `src` values; 4. Version matrix; … |
| [45 — OAuth](../../45-OAuth/cheatsheet.md) | 13 | 1. Identify the grant in five seconds; 2. Authorisation request parameters; 3. Token response fields; 4. PKCE — the only test that matters; … |
| [46 — Tokens](../../46-Tokens/cheatsheet.md) | 18 | 1. Identify the token in one glance; 2. JOSE header members; 3. Registered claims (RFC 7519 §4.1); 3a. OIDC claims; … |
| [47 — Authentication](../../47-Authentication/cheatsheet.md) | 16 | The one rule; The one test; Altitude ladder; Order of operations; … |
| [53 — Frida](../../53-Frida/cheatsheet.md) | 12 | The four commands that start every session; Setup; CLI; Java API; … |
| [54 — Objection](../../54-Objection/cheatsheet.md) | 16 | 1. CLI; 2. Session hygiene — the four commands that prevent most problems; 3. Generic REPL commands; 4. `android hooking` — reconnaissance; … |

## I need to read the app's data

On disk, in the WAL, in the backup, in the logs, in `dumpsys`, and in the KeyStore that prevents extraction but not use.

| Sheet | Sections | Read it for |
|---|---:|---|
| [09 — Android App Internals](../../09-Android-App-Internals/cheatsheet.md) | 17 | 1. Identity — package, UID, appId, userId; 2. Package / UID inspection commands; 3. `/data/system/packages.list`; 4. `/data/system/packages.xml`; … |
| [21 — App Sandbox](../../21-App-Sandbox/cheatsheet.md) | 16 | The one paragraph; UID arithmetic; Network GIDs (`platform.xml` → supplementary groups); Reading a process's sandbox; … |
| [27 — ContentProviders](../../27-ContentProviders/cheatsheet.md) | 21 | URI anatomy; Manifest attributes; `<grant-uri-permission>` path matching; Protection levels; … |
| [33 — Storage](../../33-Storage/cheatsheet.md) | 12 | Storage roots for one package; Subdirectories of the CE/DE tree; Availability by device state; Reachability: three gates, all must agree; … |
| [34 — Cryptography](../../34-Cryptography/cheatsheet.md) | 18 | The four commands that matter; Decision table — what to use; Modes; The transformation-string trap; … |
| [48 — Biometrics](../../48-Biometrics/cheatsheet.md) | 16 | The one test; Authenticator constants; `canAuthenticate()` return codes; `onAuthenticationError` codes worth forcing; … |
| [49 — KeyStore](../../49-KeyStore/cheatsheet.md) | 12 | The one sentence; The stack; `KeyGenParameterSpec` — the options that decide severity; `KeyInfo` — what you actually got; … |
| [60 — ADB](../../60-ADB/cheatsheet.md) | 17 | The 24-byte message header; Message types; Stream rules; Service strings (the `A_OPEN` payload); … |

## I need to reach it from another app

The IPC surface, from the position of a malicious app rather than from `adb shell` -- which holds privileges an app does not.

| Sheet | Sections | Read it for |
|---|---:|---|
| [24 — IPC](../../24-IPC/cheatsheet.md) | 14 | Mechanism reachability; Permission protection levels; Identity APIs; `clearCallingIdentity` — the four bugs; … |
| [25 — Binder](../../25-Binder/cheatsheet.md) | 15 | 1. Device nodes; 2. ioctl commands; 3. Structures; 4. `BC_` — commands you send; … |
| [26 — Intent](../../26-Intent/cheatsheet.md) | 14 | 1. Intent fields; 2. Common actions; 3. Common categories; 4. Resolution matching rules; … |
| [27 — ContentProviders](../../27-ContentProviders/cheatsheet.md) | 21 | URI anatomy; Manifest attributes; `<grant-uri-permission>` path matching; Protection levels; … |
| [28 — Services](../../28-Services/cheatsheet.md) | 18 | The three shapes; `onStartCommand` return values; `bindService` flags; `<service>` attributes; … |
| [29 — BroadcastReceivers](../../29-BroadcastReceivers/cheatsheet.md) | 14 | Enumeration; Protected broadcasts; Sending; Frida; … |
| [30 — Activities](../../30-Activities/cheatsheet.md) | 11 | Launch modes; `taskAffinity`; Task-affecting `FLAG_ACTIVITY_*`; Caller identity; … |
| [31 — Fragments](../../31-Fragments/cheatsheet.md) | 18 | The one-line facts; The reflective path, API 35 **[m]**; `isValidFragment`, API 35, exact **[m]**; The three gate states; … |
| [32 — Manifest](../../32-Manifest/cheatsheet.md) | 16 | Read it three ways — always; THE FIRST THING TO CHECK: targetSdkVersion; `<manifest>`; `<application>` — the highest-yield element; … |
| [43 — WebView](../../43-WebView/cheatsheet.md) | 11 | 1. WebSettings defaults by targetSdkVersion — the table **(M)**; 2. Severity, honestly; 3. Commands; 4. Static analysis; … |

## I am staring at native code

ELF layout, JNI registration, the calling convention, and the two ways a perfectly-installed hook changes nothing.

| Sheet | Sections | Read it for |
|---|---:|---|
| [15 — Native Code](../../15-Native-Code/cheatsheet.md) | 14 | 1. ELF header — ELF64 / ELF32; 2. Program headers — the loader's table; 3. Section headers — the tools' table; 4. Dynamic array (`DT_*`); … |
| [16 — JNI](../../16-JNI/cheatsheet.md) | 15 | 1. Type descriptors; 2. Name mangling; 3. The calling convention; 4. Registration; … |
| [17 — Libraries](../../17-Libraries/cheatsheet.md) | 15 | Ring classification; Bionic vs glibc — what changes for exploitation; Platform library quick reference; Enumeration commands; … |
| [18 — ARM](../../18-ARM/cheatsheet.md) | 18 | Registers — AArch64; Registers — ARM32 (armeabi-v7a); AAPCS64 at a glance; Condition codes; … |
| [19 — Memory](../../19-Memory/cheatsheet.md) | 14 | 1. `/proc/<pid>/maps` — field by field; 2. Page-protection flags; 3. `/proc/<pid>/smaps` — counters, field by field; 4. Allocator by Android version; … |
| [57 — Ghidra](../../57-Ghidra/cheatsheet.md) | 13 | The first five minutes; Setup; Keyboard; The JNIEnv problem — fix this FIRST; … |
| [58 — IDA](../../58-IDA/cheatsheet.md) | 14 | Editions — what you can actually do [D]; Keyboard [D — verify on your build]; Headless [D]; IDAPython essentials; … |
| [59 — radare2](../../59-radare2/cheatsheet.md) | 21 | The grammar in one table; Launching; Info — no analysis required, fast on any size; Analysis — the expensive family; … |
| [65 — Hooking](../../65-Hooking/cheatsheet.md) | 15 | 1. The five hook types; 2. Verified AArch64 encodings; 3. The three patch forms; 4. Branch and address-formation reach; … |
| [68 — ReverseEngineering](../../68-ReverseEngineering/cheatsheet.md) | 23 | The loop; Evidence tiers; Question states; The first ten commands; … |

## I need to prove this finding

Threat model, reproduction from an app uid, evidence, honest severity. A sweep produces leads; adjudication produces findings.

| Sheet | Sections | Read it for |
|---|---:|---|
| [47 — Authentication](../../47-Authentication/cheatsheet.md) | 16 | The one rule; The one test; Altitude ladder; Order of operations; … |
| [51 — DynamicAnalysis](../../51-DynamicAnalysis/cheatsheet.md) | 14 | The pipeline; Device posture — 40 seconds, run it first; The nine channels; Altitudes — pick the lowest that works; … |
| [52 — StaticAnalysis](../../52-StaticAnalysis/cheatsheet.md) | 13 | The pipeline; Five-minute pass; The grep catalogue; The triage decision table; … |
| [71 — OWASP Mobile](../../71-OWASP-Mobile/cheatsheet.md) | 13 | 1. The four artefacts; 2. MASVS categories at a glance; 3. Every control, and what it actually requires; 4. Identifier schemes; … |
| [72 — RealWorldFindings](../../72-RealWorldFindings/cheatsheet.md) | 18 | The three units; The three gates; Gate 1 — how detectors manufacture false positives; Gate 2 — the vantage rule; … |
| [74 — CaseStudies](../../74-CaseStudies/cheatsheet.md) | 18 | The six cases in one table; Symptom to first hypothesis; The H/P/R/E/O/V block; Evidence ladder — a claim inherits its WEAKEST rung; … |

*No sheet yet: `80`.*

## Nothing works and I do not know why

Debug the tool before you debug the app. Most of this band is a liveness check that nobody ran.

| Sheet | Sections | Read it for |
|---|---:|---|
| [51 — DynamicAnalysis](../../51-DynamicAnalysis/cheatsheet.md) | 14 | The pipeline; Device posture — 40 seconds, run it first; The nine channels; Altitudes — pick the lowest that works; … |
| [53 — Frida](../../53-Frida/cheatsheet.md) | 12 | The four commands that start every session; Setup; CLI; Java API; … |
| [54 — Objection](../../54-Objection/cheatsheet.md) | 16 | 1. CLI; 2. Session hygiene — the four commands that prevent most problems; 3. Generic REPL commands; 4. `android hooking` — reconnaissance; … |
| [60 — ADB](../../60-ADB/cheatsheet.md) | 17 | The 24-byte message header; Message types; Stream rules; Service strings (the `A_OPEN` payload); … |
| [62 — Magisk](../../62-Magisk/cheatsheet.md) | 14 | Install / flash; Which partition do I patch?; Verify installation; Filesystem layout; … |
| [66 — Instrumentation](../../66-Instrumentation/cheatsheet.md) | 17 | The gate — measured matrix **[M]**; Startup ordering **[M]**; Identity inside the process **[M]**; Vantage: shell vs instrumented app **[M]**; … |
| [77 — UsefulCommands](../../77-UsefulCommands/cheatsheet.md) | 17 | Connection; Files; Install; Packages; … |

