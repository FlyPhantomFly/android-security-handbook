# 39 — Emulator Detection: FAQ

Real questions, including the ones people are embarrassed to ask. Every number below was measured on
a **Redmi M2101K6P** (Android 11 / API 30, arm64) and a **Pixel_6_Pro_API_35** AVD
(Android 15 / API 35, x86_64).

---

### 1. What actually *is* an emulator? I use one every day and I have never thought about it.

A program that pretends to be a phone well enough that Android boots on it. The Android Emulator is a
fork of **QEMU**, an open-source machine emulator, configured to present a synthetic set of hardware
devices that Android's kernel knows how to drive.

The important nuance is that a modern Android Emulator on an x86 host does not *emulate* the CPU at
all. It **virtualises**: the guest's x86 instructions run on your real x86 CPU, with a hypervisor
(KVM on Linux, Hyper-V on Windows, Hypervisor.Framework on macOS) trapping only the privileged ones.
That is why it is fast, and it is the mechanical reason the "emulators are slow" folklore is wrong.

---

### 2. What are "goldfish" and "ranchu"? They sound made up.

They are made up — they are Google's internal names for the virtual hardware platform.

**goldfish** was the original: a set of invented devices (a timer, a framebuffer, a battery, a "pipe"
for talking to the host) with no real-world counterpart. **ranchu** is its successor, built on
**virtio**, the standard paravirtualised device interface used across Linux virtualisation.

Current AVDs are ranchu — `Build.HARDWARE` reads `ranchu` — but a few goldfish drivers survive
alongside the virtio ones, which is why `/dev/goldfish_sync` still exists on a device that calls
itself ranchu. That hybrid trips people up constantly.

---

### 3. Is emulator detection the same thing as root detection?

No, and conflating them is the most common conceptual error in this area.

**Root detection asks about privilege**: has someone gained UID 0 on this device? **Emulator
detection asks about hardware**: is this a physical phone at all?

The signal sets barely overlap. Root detection reads `su`, Magisk artefacts, mount state and
`/proc/self/maps`. Emulator detection reads virtual hardware: properties, device nodes, sensors, the
ABI. The only genuine overlap is the "this is not a retail build" family (`test-keys`, `userdebug`),
which is NOISY for both because it is also true of every custom ROM.

The clarifying case is the phone this chapter was measured on: a **rooted real device**. It passes
every emulator check and fails every root check. An app that implements only one of the two controls
has covered half the problem.

---

### 4. Why do apps care? Isn't an emulator harmless?

One emulator is harmless. **Five hundred of them are a fraud farm.**

That is the honest reason, and it is a better reason than the one usually given. An attacker with one
rooted phone is one attacker. An attacker with a desktop running fifty emulator instances, each
restored from a snapshot to a known-good device identity, can create accounts, farm referral bonuses,
spoof GPS for delivery incentives or run game bots at industrial scale.

Emulator detection does not prevent that. It raises the per-instance cost from "clone a VM" to "buy
another phone", which changes the economics of an attack that depends on volume. Framing it as fraud
economics rather than security makes every downstream decision clearer.

---

### 5. I copied the emulator check from the top Stack Overflow answer. Is it fine?

Almost certainly not. Measured on a stock Android 15 / API 35 AVD, **every clause of that function is
false**:

```java
Build.FINGERPRINT.startsWith("generic")     // fingerprint is google/sdk_gphone16k_x86_64/...
|| Build.MODEL.contains("Emulator")         // model is sdk_gphone16k_x86_64
|| Build.MODEL.contains("Android SDK built for x86")
|| Build.MANUFACTURER.contains("Genymotion")
|| (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
|| "google_sdk".equals(Build.PRODUCT)
```

It returns `false` on a current emulator. Your control does not exist.

The failure mode is what makes this so persistent: a **silent false negative**. Nothing crashes,
nothing logs, no support ticket is raised. It just quietly stops working and nobody finds out. Run
your check against a current AVD in CI and fail the build if it does not fire.

---

### 6. Really? `/dev/qemu_pipe` doesn't exist any more?

Really. It is the single most-cited emulator check in the field and it was measured **absent** on
API 35 — not "permission denied", genuinely `ENOENT`.

What exists instead:

```
crw-rw-rw- 1 system system 10, 121 goldfish_address_space
crw-rw-rw- 1 system system 10, 120 goldfish_pipe_dprctd
crw-rw-rw- 1 system system 10, 119 goldfish_sync
```

The pipe was renamed to `goldfish_pipe_dprctd` — "deprecated", named by the very kernel module that
still provides it. `/dev/socket/qemud`, `/system/bin/qemu-props` and
`/system/lib/libc_malloc_debug_qemu.so` are all gone too.

---

### 7. Why does my Frida hook on `SystemProperties.get` not change `Build.MODEL`?

Because you are not too early — you are far too late.

Every `Build` field is a `public static final String` assigned in a **static initialiser**. Static
initialisers run once, when the class is first loaded, which for `android.os.Build` is during process
startup. `SystemProperties.get` was called then and will never be called again for that field. The
value is now a constant sitting in the class's static storage.

Hooking the getter afterwards cannot retroactively change a constant. Write the field:

```javascript
Java.use("android.os.Build").MODEL.value = "M2101K6P";
```

This is the single most common "my hook does not work" in the whole chapter, and the fix is not a
better hook — it is a different mechanism.

---

### 8. I tested a `/proc/modules` check from `adb shell` and it worked perfectly. Why does it fail in my app?

Because **`adb shell` is not an app**, and this is the methodology trap that catches the most people.

The shell runs as uid 2000 in the SELinux domain `u:r:shell:s0`, with a long list of supplementary
groups. An app runs as an app uid in `u:r:untrusted_app:s0`. The app can see strictly less.

Measured, from an app, on **both** devices:

| Path | Shell | App |
|---|---|---|
| `/proc/cpuinfo` | readable | readable |
| `/proc/self/mounts` | readable | readable |
| `/proc/modules` | readable | **EACCES** |
| `/proc/tty/drivers` | EACCES | **EACCES** |
| `/proc/cmdline` | EACCES | **EACCES** |

`/proc/modules` from the shell shows four goldfish kernel modules and looks like a perfect signal.
From an app it is permission denied. Always prove reachability from an app.

---

### 9. How many properties can an app actually see?

Fewer than you can. Measured with `__system_property_foreach` in each context:

| Domain | AVD | Redmi |
|---|---|---|
| `root` | **~1055-1062** | n/a |
| `shell` (uid 2000) | **~673-678** | **863** |
| `untrusted_app` | **~633-638** | **816** |

**419 of the AVD's properties are invisible to an app.** The mechanism is SELinux property contexts:
each key has a type, and a domain without read permission on that type never gets that region mapped.

Concretely: `ro.boottime.qemu-props` has type `boottime_prop`. The shell reads `7137914100`; an app
reads an empty string. So the whole `ro.boottime.*` family naming emulator-only `init` services —
which looks like a goldmine from the shell — is unreachable from an app.

---

### 10. Someone told me to time a benchmark because emulators are slow. Is that right?

It is exactly backwards, and this was measured rather than argued. Identical C source, same NDK,
running under an **app uid** on both devices — a 20-million-iteration integer loop:

| Device | ns per iteration |
|---|---|
| Redmi M2101K6P (real arm64 phone) | **3.516** |
| Pixel_6_Pro_API_35 AVD (x86_64) | **2.398** |

The emulator was **1.47× faster**.

Even binary translation does not rescue the claim. Running the **arm64** build on the x86_64
emulator, where every ARM instruction is translated to x86, gave **3.026 ns/iter** — still faster than
the real ARM phone, because the translator compiles hot blocks once and reuses them.

Do not ship a timing threshold. Phones vary by an order of magnitude across the price range, and the
same phone varies by a factor of two between cold and thermally throttled.

---

### 11. Is there *any* legitimate use of a timing check?

One, and it is not emulator detection. Comparing `CLOCK_MONOTONIC` against `CLOCK_THREAD_CPUTIME_ID`
can spot a **single-stepping debugger**, where the discrepancy is orders of magnitude rather than
percent. That is anti-debug and it belongs to
[38-TamperDetection](../38-TamperDetection/README.md). This chapter grades every timing signal INFO
and uses none of them in any scoring example.

---

### 12. My check flagged a real customer's phone. How?

You probably matched on a property **name** containing `qemu`. Measured, from an app, on a retail
Xiaomi:

```
$ adb shell "run-as com.pentest.ch39 getprop | grep -iE 'qemu|goldfish|ranchu'"
[qemu.hw.mainkeys]: [0]
[ro.kernel.qemu.gles]: [0]
```

**Two `qemu`-named properties on a real phone**, and neither is set on the emulator. `qemu.hw.mainkeys`
is a legacy key controlling whether the navigation bar is drawn; OEMs adopted it from the emulator's
configuration and kept it. The heuristic reports this phone as an emulator and the emulator as a
phone.

Two other common false-positive sources: `Build.BOOTLOADER == "unknown"` is true on **both** devices
measured here, and any check for `test-keys` flags every custom ROM on real hardware.

Match on **specific keys against specific values**, never on a substring of a key name.

---

### 13. What is the single best signal an app can read?

For a Java-only app, **the sensor population** — not the count, the vendors.

| | Redmi | AVD |
|---|---|---|
| Sensor count | 41 | 18 |
| Distinct vendors | qualcomm, TDK-Invensense, xiaomi, XiaoMi, Rohm, akm, ams AG, Xiaomi | AOSP, The Android Open Source Project |
| Vendored AOSP | **0/41** | **18/18** |

It is strong for a structural reason: it is a **population, not a value**. Every AVD sensor comes from
one synthetic HAL, so they all carry the same vendor string. A real phone has six different physical
parts from six suppliers, each contributing its own driver string. Faking that means inventing a
self-consistent bill of materials, and an *inconsistent* fake is itself a signal.

If you can ship native code, the ABI mismatch and the CPUID `hypervisor` bit are stronger still.

---

### 14. What does "the ABI mismatch" mean, and why is it hard to fake?

A physical arm64 phone advertises only ARM ABIs. The measured AVD advertises `x86_64, arm64-v8a` and
sets `ro.dalvik.vm.native.bridge` to `libndk_translation.so` — a translator that converts ARM machine
code to x86 at run time, so that apps shipping only ARM libraries still work.

The strong version does not read the property at all. A native binary knows what it was compiled for
at **compile time** — a constant in `.rodata`, not a value read from anywhere:

```c
#if defined(__aarch64__)
#  define BUILD_ARCH "arm64-v8a"
#endif
    __system_property_get("ro.product.cpu.abi", abi);
    if (strcmp(BUILD_ARCH, abi) != 0) { /* translation is happening */ }
```

Demonstrated by running the arm64 build on the x86_64 AVD: `compiled=arm64-v8a platform=x86_64`.

To defeat it, the attacker must make the platform *claim* `arm64-v8a` while still translating — and
then every genuinely-x86 component disagrees. It is a coherent-lie problem rather than a one-value
problem, which is a different order of work.

---

### 15. What is the `hypervisor` flag and can it be spoofed?

On x86, bit 31 of `ECX` from `CPUID` leaf 1 is the "hypervisor present" bit. Real silicon leaves it
clear; virtualisation software sets it by convention so guests can tell they are virtualised. Linux
surfaces it as the `hypervisor` flag in `/proc/cpuinfo`, which apps can read.

The guest cannot clear it, because the value is produced by the CPU when the hypervisor traps the
`CPUID` instruction — it never passes through guest-controlled memory. You can hook the *app's read*
of `/proc/cpuinfo`, but you cannot change what the CPU reports.

**One critical caveat**: there is no ARM equivalent. An arm64 emulator image has no such bit, so a
`false` here is meaningless on arm64. Gate the check on `Build.SUPPORTED_ABIS` containing an x86 ABI,
or it is correct on one architecture and simply wrong on the other.

---

### 16. Why is a single `isEmulator()` boolean bad if the checks inside it are good?

Three reasons, and only the third is about the checks.

**It collapses to one return value.** Whatever the app learns, the attacker gets exactly one branch to
control:

```javascript
Java.use("com.example.Security").isEmulator.implementation = function () { return false; };
```

Add fifty more checks inside and that hook still wins. Effort spent behind a single boolean buys
nothing.

**It short-circuits.** `||` stops at the first `true`, so "one weak signal fired" and "eleven signals
including two HARD ones fired" produce an identical value — wildly different confidence levels,
indistinguishable. Worse, the later checks never execute on the devices where they would be most
informative, so telemetry cannot tell you which of your checks work.

**It throws away the evidence and keeps the conclusion**, which is exactly backwards. The evidence is
what a server needs, what makes a false positive diagnosable, and what lets you change policy without
an app release.

---

### 17. Where should the decision be made, if not in the app?

On your server, and the shape matters:

1. Your **server** generates a single-use nonce.
2. The app gathers **evidence** — a score plus which signals fired — and requests a Play Integrity
   token bound to that nonce.
3. The app sends the action, the evidence and the token. **It never branches on integrity.**
4. The server verifies the token's signature, verifies the nonce matches and has not been used, and
   applies policy.

The nonce stops replay of a token captured from a genuine device. The token is opaque to the app, so
there is no client-side boolean to hook. The evidence is advisory — an attacker can lie about it —
but they cannot forge the token. That asymmetry is the whole design.

A nice property: if the hardware says "fine" and the client-reported evidence says "emulator", the
disagreement is itself information. An architecture that keeps both can see it; one that keeps a
boolean cannot.

---

### 18. Isn't attestation just another check I can hook?

No, and this is the one genuine exception in the chapter. The signing key lives in the device's
Trusted Execution Environment and never enters the app's address space. You cannot extract it and you
cannot forge a chain rooted in it. On an emulator there is no TEE, so every key attests as `SOFTWARE`
with an empty `hardwareEnforced` list.

**But there is a trap, and [50-HardwareBackedSecurity](../50-HardwareBackedSecurity/README.md)
measured it: on an emulator the attestation chain still verifies perfectly.** A verifier that checks
"does this chain validate?" and stops has learned nothing. It must inspect the **security level** and
reject a chain rooted anywhere other than the manufacturer roots.

The same chapter measured something even more pointed on the Redmi:
`ro.boot.verifiedbootstate` read `green` while a TEE-signed attestation from the same device seconds
later reported `verifiedBootState=Unverified, deviceLocked=false`. **The property lied; the hardware
did not.** That is the concrete argument for attestation over any `getprop`-based check.

---

### 19. How do I test an app for emulator detection, in order?

1. **Run it on a stock, unmodified current AVD.** Change nothing first. If it works normally, the
   detection is absent or dead and you have your finding in five minutes. People skip this constantly
   and it is the highest-value step.
2. Read `adb logcat` during startup. Many apps log the reason.
3. Map the surface statically: `python3 -B scripts/emu-signal-map.py app.apk`.
4. **Trace before hooking**: `frida -U -f <pkg> -l scripts/emu-trace.js`. Find out which signal fires,
   not which exist.
5. Neutralise **only** that signal, at the lowest altitude that works.
6. Exercise the sensitive flows — payment, login, export. Apps re-check.
7. **Test the server.** Perform the gated action and see whether anything independent notices.

---

### 20. Why does everyone say use `-f` and not `-p` with Frida?

Because `-p` attaches to a process that has already decided.

Checks run in three places that all execute before you can attach to a running app: a `static { }`
initialiser, `Application.onCreate()`, and — for native checks — `JNI_OnLoad`, which runs the moment
`System.loadLibrary` is called. `frida -U -f <pkg>` spawns the process **suspended** and installs
hooks before any app code runs.

If your trace comes back completely empty, this is the first thing to check.

---

### 21. My trace shows nothing but the app clearly refuses. What now?

In order:

1. Confirm you used `-f`, not `-p`.
2. Confirm frida-server is running and version-matched: `frida-ps -U`.
3. Turn on native tracing. If the Java trace is silent and the native one is not, the check is in C
   and a `Java.use` hook will never see it. Hook `__system_property_get` in libc.
4. Check `adb logcat -b crash` and `/data/tombstones` — a tombstone naming a `.so` means a native
   check called `abort()`.
5. If a hook installs and changes nothing, consider **inlining** before assuming the hook is broken.
   [65-Hooking](../65-Hooking/README.md) measured a perfectly installed hook on an exported symbol
   doing nothing because **zero `bl` instructions targeted it**;
   [18-ARM](../18-ARM/README.md) patched a check to `return 1`, verified it returned 1, and the
   caller still refused. `frida-trace` showing no hits on a symbol that exists is the signature.

---

### 22. Can I just spoof properties on the emulator instead of hooking the app?

Partly, and the limits are the interesting bit. `setprop` cannot change `ro.` properties — the
property service refuses. Magisk's `resetprop` writes the trie directly and can:

```bash
resetprop ro.kernel.qemu ''
resetprop ro.hardware qcom
resetprop ro.build.characteristics default
```

[`scripts/harden-avd.sh`](scripts/harden-avd.sh) applies a consistent profile and then re-measures to
show what it did *not* fix. The honest answer is that it fixes every SOFT signal and none of the HARD
ones: `/dev/goldfish_*` are kernel drivers, the 18 AOSP-vendored sensors come from the HAL, the
`hypervisor` bit comes from the host CPU, and there is still no TEE.

**Property spoofing defeats the checks people write, not the checks that are available.** That is the
whole lesson.

---

### 23. Why did my NDK binary segfault on the emulator before printing anything?

Almost certainly the **16 KiB page size**. NDK r25c defaults to 4 KiB ELF segment alignment. Android
15 emulator images tagged `page_size_16kb` — the `sdk_gphone16k_*` family — run a 16 KiB-page kernel,
and the loader cannot map a 4 KiB-aligned binary there. The process dies with SIGSEGV **before
reaching `main`**.

Verified while writing this chapter: `int main(void){return 42;}`, built without the flag, exits
**139** on that AVD. Nothing in the output mentions page size, so you will blame your own code first.

The fix:

```bash
clang -Wall -Wextra -O2 -Wl,-z,max-page-size=16384 -o probe probe.c
```

[70-VulnerabilityResearch](../70-VulnerabilityResearch/README.md) hit the same wall independently.

---

### 24. `adb push` says "remote secure_mkdirs() failed". What?

Git Bash / MSYS is rewriting `/data/local/tmp` into a Windows path before `adb` sees it. Prefix the
command:

```bash
MSYS_NO_PATHCONV=1 adb push probe /data/local/tmp/probe
```

The related trap: SDK tools like `aapt2` are native Windows binaries and do not understand
`/c/Users/...` paths, so they report "failed to load XML file" on a file that plainly exists. Convert
with `cygpath -w`.

---

### 25. How do I rate a bypassed emulator check in a report?

By asking what the **server** does without it, never by rating the check.

| Situation | Rating |
|---|---|
| No detection; server has no device signal; high-value transactions | MEDIUM |
| Detection present but **DEAD**; no server control | MEDIUM |
| Detection works, bypassed in 10 minutes, server independently risk-scores | LOW / INFO |
| Detection false-positives on retail devices | MEDIUM |
| Server trusts a client-supplied `deviceOk` flag | **HIGH** |
| Gates a cosmetic feature | INFO |

And the wording matters. *"Emulator detection was bypassed"* describes an activity. **"With emulator
detection bypassed, N accounts were provisioned from a single host in M minutes, and the server
applied no rate limit or device-reputation control"** describes an impact. Only the second is a
finding.

---

### 26. Is telling a developer their check is dead really worth more than bypassing it?

Frequently, yes. If an app ships `/dev/qemu_pipe` and `Build.FINGERPRINT.contains("generic")`, you
have not found a weak control — you have found a control that **has never fired in production**. The
developer believes they are covered. Nobody has told them otherwise, because the failure mode
produces no error.

Confirming it is trivial: run the app on a stock current AVD and watch it work normally. No Frida, no
bypass, five minutes.

---

### 27. Should I implement emulator detection at all?

The case against is strong: it is a client-side control in a threat model where the client is the
adversary; the signal set demonstrably rots, so it becomes a control that provides *false* assurance;
it generates false positives that block paying customers on retail hardware; and the evidence it
gathers is a high-entropy device fingerprint with privacy exposure.

The case for is narrower but real: **cost imposition**. Raising the per-instance cost from "clone a
VM" to "own a phone" changes the economics of volume-dependent attacks.

If you ship it: make it a **risk input feeding server policy**, never a gate; keep the evidence, not a
boolean; test it against a current AVD in CI; and budget it as fraud engineering rather than security
engineering, because that is what it is.

---

### 28. Malware detects *my* sandbox using this. What do I do?

Same signals, adversary reversed. The mitigations are the inverse of this chapter: analyse on physical
hardware where possible, and use a hardened AVD with patched properties and a plausible sensor set
where not.

Be honest in your notes about which environment produced which observation. A sample that behaves
differently on hardware is itself a finding.

And know the limit: a sample that refuses to decrypt its payload unless a genuine TEE-signed
attestation is available **cannot be analysed in an emulator at all**, and unlike a property check you
cannot patch past it, because the payload really is encrypted under a key the server only releases to
an attested device. See [69-MalwareAnalysis](../69-MalwareAnalysis/README.md).

---

### 29. Does MobSF find emulator detection?

It flags the strings. It does not grade them, and — this is the point of the chapter — it **cannot
tell a DEAD check from a live one**, because that requires running against a current AVD.

There is a deeper structural problem, recorded in [55-MobSF](../55-MobSF/README.md): MobSF's dynamic
analysis runs *in an emulator*. An app with working emulator detection produces a dynamic report
about the app refusing to run. **A clean MobSF dynamic report on an app with emulator detection means
the analysis was blocked, not that the app is safe.**

Treat every automated hit as a lead and grade it yourself.

---

### 30. This chapter's tables disagree with what I measured. Who is wrong?

Possibly neither, and working out which is the actual skill.

Every table here names its two devices and their API levels. A DEAD grade measured on API 35 is not a
claim about API 28. If your AVD is arm64 (Apple silicon), the ABI-mismatch and `hypervisor` signals
vanish entirely and both HARD grades become inapplicable. If your phone is not a Xiaomi, the
`qemu.hw.mainkeys` NOISY grade may not reproduce.

So ask: *is the chapter wrong, or did it measure a different thing?* Then record your own numbers with
your own device details next to them. That is what [Lab 01](labs/lab-01-measure-both-sides.md) is
for, and finding a disagreement is one of its success criteria — the signal set rots, and an analyst
who can only recite last year's list will be wrong next year.

---

## Related chapters

- [37-RootDetection](../37-RootDetection/README.md) — the sibling control, same trust boundary
- [38-TamperDetection](../38-TamperDetection/README.md) — repackaging and anti-instrumentation
- [67-BypassingProtections](../67-BypassingProtections/README.md) — owns the bypass methodology
- [50-HardwareBackedSecurity](../50-HardwareBackedSecurity/README.md) — attestation, the signal that holds
- [22-SELinux](../22-SELinux/README.md) — why `boottime_prop` is invisible to apps
- [62-Magisk](../62-Magisk/README.md) — `resetprop`
- [69-MalwareAnalysis](../69-MalwareAnalysis/README.md) — the same signals, adversary reversed
- [60-ADB](../60-ADB/README.md) — why the shell is not an app
