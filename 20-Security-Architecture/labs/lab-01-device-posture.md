# Lab 01 — Device posture, and the device that lies about it

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Chapter:** [20 — Security Architecture](../README.md) §3.1, §3.8, §4.5, §5.5
**Prerequisites:** [`adb` installed and a device or emulator connected](../../60-ADB/README.md).
No root, no Frida, no Android Studio, and no programming.
**Reading:** [§3.1 Verified Boot and AVB 2.0](../README.md#31-verified-boot-and-android-verified-boot-20-avb), [§4.5, which traces `verifiedbootstate` from Java
all the way down to silicon](../README.md#45-tracing-one-complete-path-is-this-devices-boot-verified-from-java-to-silicon), and
[06-Android-Architecture/scripts/device-posture.sh](../../06-Android-Architecture/scripts/device-posture.sh),
which you will write your own version of and then compare against.

---

## Objective

Extract every integrity-relevant signal from an Android device, explain what each one means, and —
the part that actually matters — classify each as **forgeable** or **not forgeable** by an attacker
with root.

By the end you will have a reusable posture script, and you will have personally watched a device
report `verifiedbootstate=green`, `flash.locked=1` and `release-keys` while being rooted, running
frida-server, carrying a patched boot image and holding an interception CA in its *system* trust
store. Not read about it. Watched it, on hardware, with three independent commands.

## Why this lab exists

Every mobile engagement starts with an unstated assumption about the device under test. If you do
not record the device's state, three things follow, and all three are bad:

1. **You cannot explain your own results.** A control that behaved oddly six weeks ago is
   unexplainable once you have forgotten whether the phone was rooted.
2. **You cannot reproduce them.** "It worked on my device" is not a finding.
3. **You miss the finding that is often the largest in the whole test.** On a corporate fleet
   engagement, a device stack two years behind on security patches outweighs almost anything you
   will find in the app.

There is a fourth reason, and it is the one this lab is really built around. Almost every published
"device integrity check" reads `getprop`. This lab makes you prove, by measurement, that `getprop`
is attacker-controlled data — and then shows you the two places where the truth survives.

> **Mental Model**
> A posture signal is not a fact about the device. It is a **claim**, made by some component, that
> reached your process by some path. The only question that matters is: *who could have edited the
> claim between its origin and your read?* Every signal in this lab is classified by answering that
> one question, and nothing else.

---

## Setup

### What you need

One of the following, in descending order of usefulness:

- **Best: two devices** — one stock and unrooted, one rooted. The diff between them is the lab.
- **Good: one rooted physical device.** You will see the forged values directly.
- **Adequate: one stock physical device.** You will see honest values and must take the forged ones
  from this document.
- **Fallback: an emulator** (Android Studio → Device Manager → any Google APIs image). Works for
  every step except the block-device reads in the *Going further* section. An emulator's posture is
  *differently* dishonest, which is instructive in its own right.

### Confirm the connection, and identify what you are talking to

```bash
# host
adb devices -l
adb shell echo ok
```

Real output from the device this lab was written against — **two devices were attached**, which is
itself worth noticing, because every subsequent `adb shell` would have been ambiguous:

```text
List of devices attached
84f7a024               device product:sweetin model:M2101K6P device:sweetin transport_id:1
emulator-5554          device product:sdk_gphone16k_x86_64 model:sdk_gphone16k_x86_64 device:emu64xa16k transport_id:2
```

> **Warning — always pin the serial.**
> With more than one device attached, `adb shell getprop` fails with `adb: more than one device`, or
> worse, silently picks one if you have `ANDROID_SERIAL` set from a previous session. Every command
> in this lab should carry `-s`:
>
> ```bash
> # host
> export D=84f7a024          # your serial from the list above
> adb -s "$D" shell echo ok
> ```
>
> This is not pedantry. Chapter 52 of this repository watched a device silently swap mid-session and
> almost attributed one phone's results to another. Pin the serial in the first minute.

---

## Steps

### Step 1 — Collect the identity and build signals

Run these **one at a time** and write each value down before running the next. The point is to see
each value in isolation and form a hypothesis about it; pasting the whole block gives you a wall of
text you will not read.

```bash
# adb shell
getprop ro.product.manufacturer
getprop ro.product.model
getprop ro.product.device
getprop ro.build.fingerprint
getprop ro.build.type
getprop ro.build.tags
getprop ro.build.version.release
getprop ro.build.version.sdk
getprop ro.build.version.security_patch
getprop ro.vendor.build.security_patch
```

Measured, on the Redmi `M2101K6P`:

```text
ro.product.manufacturer         = Xiaomi
ro.product.model                = M2101K6P
ro.product.device               = sweetin
ro.build.fingerprint            = Redmi/sweetin/sweetin:11/RKQ1.200826.002/V12.5.10.0.RKFINXM:user/release-keys
ro.build.type                   = user
ro.build.tags                   = release-keys
ro.build.version.release        = 11
ro.build.version.sdk            = 30
ro.build.version.security_patch = 2021-12-01
ro.vendor.build.security_patch  = 2021-12-01
```

**What each one is telling you.**

| Property | Claim | Why a tester cares |
|---|---|---|
| `ro.build.fingerprint` | The canonical identity of this exact build: brand, device, release, build ID, incremental version, build type and tags, all in one string | It is the *only* signal that pins the build precisely enough to look up its known vulnerabilities. Record it verbatim in every report |
| `ro.build.type` | `user` (shipping), `userdebug` (shipping + root-capable shell), `eng` (development) | `userdebug` or `eng` on a device presented as production is a finding on its own |
| `ro.build.tags` | `release-keys` if signed with the OEM's private release key; `test-keys` if signed with the AOSP public test keys | `test-keys` means anyone can build a system image this device would accept as legitimate — the signing key is published in AOSP |
| `ro.build.version.security_patch` | The date of the newest Android Security Bulletin merged into this build | The single number most likely to be your highest-severity finding |
| `ro.vendor.build.security_patch` | The same, for the vendor partition | Frequently **older** than the system one. Chipset vendors patch on their own schedule, and a current system partition sitting on a stale vendor partition is a common real-world gap |

**Compute the patch delta now, in months, not days.** From `2021-12-01` to the date this lab was
written (2026-08-13) is **56 months**. Android publishes a bulletin every month, so this device is
missing roughly **56 bulletins**. That is the sentence that belongs in a report — not "the patch
level is 2021-12-01", which means nothing to a reader who does not do the arithmetic for you.

### Step 2 — Collect the Verified Boot signals

```bash
# adb shell
getprop ro.boot.verifiedbootstate
getprop ro.boot.flash.locked
getprop ro.boot.veritymode
getprop ro.boot.vbmeta.digest
getprop ro.boot.vbmeta.device_state
```

Measured on the same device:

```text
ro.boot.verifiedbootstate    = green
ro.boot.flash.locked         = 1
ro.boot.veritymode           = enforcing
ro.boot.vbmeta.digest        = e8ff1960b98291b6a5ee5ffba80da2be5cdde2594a5a79966871675a47abe7d3
ro.boot.vbmeta.device_state  = locked
```

Read that carefully before continuing, because it is the setup for the whole lab.

- `verifiedbootstate=green` means: the bootloader is locked, and every image verified against the
  **OEM's own** key. This is the strongest of the four states (`green` > `yellow` > `orange` > `red`).
- `flash.locked=1` and `device_state=locked` mean: the bootloader will refuse `fastboot flash`.
- `veritymode=enforcing` means: dm-verity will halt on a corrupt block rather than log and continue.

Taken at face value, this is a pristine, factory-locked, fully-verified device.

**It is not.** It is rooted, it runs frida-server, its boot image is patched, and its system CA
store has been replaced with a tmpfs containing an interception certificate. The next three steps
prove each of those independently.

### Step 3 — Ask the same question of a different source

Every `ro.boot.*` property is *derived*. Its origin is the kernel command line, which the bootloader
constructs and hands to the kernel, and which `init` reads at boot and copies into the property
area. So the same claim exists in two places, and comparing them is free.

```bash
# adb shell
cat /proc/cmdline | tr ' ' '\n' | grep -i androidboot
```

On this device that fails:

```text
cat: /proc/cmdline: Permission denied
```

> **Pentester's Note — this failure is a result, not an obstacle.**
> Find out *which* layer denied you before you reach for root:
>
> ```bash
> # adb shell
> id                                  # DAC identity
> id -Z                               # MAC identity
> ```
> ```text
> uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),... context=u:r:shell:s0
> u:r:shell:s0
> ```
>
> And the file itself, read with root:
>
> ```text
> -r--r----- 1 root radio u:object_r:proc_cmdline:s0  0 /proc/cmdline
> ```
>
> Mode `0440`, owner `root`, group `radio`. The shell user is uid 2000 and is not in group `radio`,
> so **DAC** refuses first; SELinux never gets a say. This matters more than it looks: an ordinary
> app is even further from `radio` than `shell` is, so **an app cannot perform this cross-check at
> all.** Remember that when you reach Step 6.

With root:

```bash
# adb shell
su -c 'cat /proc/cmdline' | tr ' ' '\n' | grep -i androidboot
```

```text
androidboot.hardware=qcom
androidboot.verifiedbootstate=orange
androidboot.keymaster=1
androidboot.vbmeta.device_state=unlocked
androidboot.vbmeta.hash_alg=sha256
androidboot.vbmeta.size=6720
androidboot.vbmeta.digest=e8ff1960b98291b6a5ee5ffba80da2be5cdde2594a5a79966871675a47abe7d3
androidboot.vbmeta.invalidate_on_error=yes
androidboot.veritymode=enforcing
androidboot.secureboot=1
androidboot.serialno=84f7a024
```

Put the two side by side. This is the core measurement of the lab:

| Claim | Kernel command line (the bootloader's word) | `getprop` (what an app reads) | Verdict |
|---|---|---|---|
| Verified boot state | `orange` | **`green`** | **forged** |
| Device state | `unlocked` | **`locked`** | **forged** |
| Bootloader lock | *(not on the cmdline)* | `ro.boot.flash.locked=1` | **forged** |
| vbmeta digest | `e8ff1960…e7d3` | `e8ff1960…e7d3` | untouched |
| verity mode | `enforcing` | `enforcing` | untouched |

**The bootloader said `orange`. The property says `green`.** `orange` means the bootloader is
*unlocked* and verified nothing at all. A root module — Magisk's `resetprop`, or APatch's
equivalent — rewrote the property in the property area after `init` had populated it, and every app
on the device now reads the rewritten value.

Notice also what was *not* forged. The vbmeta digest and the verity mode came through unchanged.
Whoever wrote that module changed exactly the three fields that detection code looks at and left the
rest alone, because changing more creates more chances to be inconsistent. **The forgery is
targeted, and that is normal.** Do not assume a device that fails one check has failed all of them.

> **Definition — the property area**
> `getprop` does not perform a lookup on demand. Every property lives in a shared memory region
> mapped read-only into every process from `/dev/__properties__/*`, written by `init`. Root can open
> those files for writing and edit the region in place. That is the whole mechanism, and it is why
> **every `getprop` value on a rooted device is attacker-controlled**. See [§4.5](../README.md#45-tracing-one-complete-path-is-this-devices-boot-verified-from-java-to-silicon).

### Step 4 — Collect the debug and encryption signals

```bash
# adb shell
getprop ro.debuggable
getprop ro.secure
getprop ro.crypto.state
getprop ro.crypto.type
getenforce
```

```text
ro.debuggable    = 0
ro.secure        = 1
ro.crypto.state  = encrypted
ro.crypto.type   = file
Enforcing
```

Again: all five say "hardened production device", on a device that is rooted. `ro.debuggable=0` is
true *as a property* and irrelevant *as a control*, because root does not need `ro.debuggable` to
attach to anything.

`ro.crypto.type=file` is the one genuinely useful value here: it says **File-Based Encryption**, so
each user's data is encrypted with per-file keys and the Credential-Encrypted directory is
unreadable until first unlock. The older `block` value means Full-Disk Encryption, which is a
finding on any device shipped after Android 10.

`getenforce` returning `Enforcing` is worth its own sentence. SELinux **is** genuinely enforcing
here — but the root daemon runs in a permissive-by-design domain, which you can see directly:

```bash
# adb shell
su -c id
```
```text
uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0
```

`u:r:magisk:s0`. SELinux is enforcing a policy that contains a domain built to be unconstrained.
"Enforcing" answers *is the mechanism on*, not *is the policy sound*.

### Step 5 — Confirm the rest of the story

Two more commands, each proving a separate compromise the properties denied.

```bash
# adb shell — is there a root binary at all?
which su
su -c id
```
```text
/system/bin/su
uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0
```

```bash
# adb shell — has the system CA store been replaced?
mount | grep -i cacerts
```
```text
APatch on /system/etc/security/cacerts type tmpfs (rw,seclabel,relatime,size=2836508k,...)
/dev/block/dm-10 on /system/etc/security/cacerts/d41b5e2a.0 type f2fs (rw,...)
/dev/block/dm-10 on /system/etc/security/cacerts/86212b19.0 type f2fs (rw,...)
```

A **tmpfs** mounted over the system CA directory, with individual certificates bind-mounted into it.
That is an interception CA promoted into the *system* store, and it invalidates any TLS test you run
here — a successful intercept would prove nothing about whether the app trusts user-installed CAs,
because the proxy CA is not a user CA any more. [35 — SSL](../../35-SSL/README.md) and
[44 — NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) both depend on that
distinction; record it before you test either.

Note also that the mount says **APatch** while the SELinux context said **magisk**. Two rooting
stacks' artefacts on one device. Never infer the rooting method from a single signal.

### Step 6 — Enumerate the Mainline modules

```bash
# adb shell
pm list packages --apex-only
```
```text
package:com.google.android.cellbroadcast
package:com.android.apex.cts.shim
package:com.android.art
package:com.google.android.adbd
package:com.android.i18n
package:com.google.android.ipsec
package:com.google.android.extservices
package:com.google.android.conscrypt
```

`ls /apex/` gives the same information with version suffixes, but on this device it needs root
(`ls: /apex/: Permission denied` as shell), whereas `pm list packages --apex-only` does not — use
the one that works unprivileged.

For at least three modules, write one sentence on why independent updatability matters. Three worth
knowing:

- **`com.android.conscrypt`** ships the TLS stack. A TLS bug can be fixed without an OS update — and
  it means the TLS behaviour of two devices on the same Android version can differ.
- **`com.android.art`** ships the runtime itself. The ART your app runs on is not a fixed function
  of the Android version, which is why [13 — ART](../../13-ART/README.md) tells you to measure
  rather than infer.
- **`com.android.media`** ships the codecs, historically the largest single source of remote
  Android vulnerabilities (the Stagefright family).

### Step 7 — Build the posture script

Write a shell script that collects everything above in one pass and prints it in a fixed order,
labelled. Fixed order matters: the point of a posture record is that you can `diff` two of them.

Requirements for yours:

- One line per signal, `name = value`, aligned.
- Print `(not set)` for an empty property rather than a blank — an absent property and an empty one
  are different facts, and the emulator in *Going further* sets several to empty.
- Include the cmdline/property comparison from Step 3, degrading gracefully when `/proc/cmdline`
  cannot be read.
- Take a `-s SERIAL` argument. You will regret it otherwise.

A reference implementation lives at
[`06-Android-Architecture/scripts/device-posture.sh`](../../06-Android-Architecture/scripts/device-posture.sh).
**Write yours first**, then read that one — the comparison is the exercise, and reading it first
turns the exercise into transcription.

> **Pentester's Note — the `--test-device` flag is the most important thing in that script.**
> Your own rooted handset trips almost every posture check. A report that lists those as *findings*
> is worthless, and worse, it destroys your credibility on the findings that are real. The flag
> records them as **methodology** — "this is my instrument, and here is how it differs from a stock
> device" — rather than as results. Build that distinction into your script on day one. Retrofitting
> it after you have written a report is exactly how test-bench artefacts reach a client.

### Step 8 — Classify every signal

This is the deliverable. Produce a table with four columns: **signal**, **what it claims**, **where
the value physically lives when an app reads it**, **can root forge it?**

The third column is the one that does the work. Do not guess at the fourth column — derive it from
the third. Here is the answer key, but fill yours in before reading it.

| Signal | Where it lives at read time | Root can forge? |
|---|---|---|
| `ro.build.*` (all) | Property area, `/dev/__properties__` | **Yes** |
| `ro.boot.*` (all) | Property area — copied there by `init` from the cmdline | **Yes** |
| `ro.debuggable`, `ro.secure` | Property area | **Yes** |
| `getenforce` | `/sys/fs/selinux/enforce` | **Yes** (`setenforce 0`, or a policy edit) |
| `/proc/cmdline` | Kernel memory, read-only to userspace | **No** — but unreadable to an app anyway |
| `Build.FINGERPRINT` in Java | Read from the property area at process start | **Yes** — same source |
| `PackageManager` signature checks | `/data/system/packages.xml`, plus the APK | **Yes** — root can edit both |
| SafetyNet / Play Integrity **basic** verdict | Evaluated partly on device | **Yes**, and routinely is |
| **Key attestation certificate chain** | Generated inside the **TEE**, signed by a key the normal world cannot read | **No** |

Everything above the last row is a claim made by software the attacker controls. The last row is a
claim made by hardware the attacker does not control, and it is the only one on the list that
survives root.

> **Under the Hood — the measurement that settles it**
> [50 — HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) pulled a TEE-signed key
> attestation from **this exact device, seconds after** reading `ro.boot.verifiedbootstate=green`.
> The attestation reported `verifiedBootState=Unverified`, `deviceLocked=false` and an all-zero
> `verifiedBootKey`.
>
> **The property lies; the hardware does not.** That is not an argument, it is a pair of
> measurements taken a minute apart, and it is the concrete reason attestation exists.

---

## Hints

<details>
<summary>Hint 1 — `getprop` returns nothing for some properties</summary>

An empty result means the property is **not set** on this device, which is often normal and is
itself information. Emulators do not set `ro.boot.verifiedbootstate`, `ro.boot.flash.locked` or
`ro.boot.vbmeta.device_state` at all — there is no bootloader to set them. Devices that shipped
before AVB 2.0 do not set `ro.boot.vbmeta.*`.

Record "not set". Do not record "green" because a blog post said that is the normal value, and do
not treat empty as `false` — a detection routine that reads an unset property as "unlocked" will
flag every emulator and no rooted phone, which is precisely backwards.
</details>

<details>
<summary>Hint 2 — how do I decide whether root can forge a value?</summary>

Ask one question: **where does the value physically live at the moment the app reads it?**

- Normal-world memory or a writable filesystem → root can change it. Every `getprop` value lives in
  a shared memory region mapped from `/dev/__properties__`, which root can write. Therefore every
  `getprop` value is forgeable, with no exceptions and regardless of how "low level" the property
  name sounds.
- Kernel memory, read-only to userspace → root can still change it, by loading a module or patching
  the kernel; and on this device the app cannot read it anyway.
- Inside the TEE, and delivered as something **signed by a key the normal world cannot read** → not
  forgeable. The signature is the whole point; the data would be forgeable without it.

The trap is reasoning by how *authoritative* a name sounds. `ro.boot.verifiedbootstate` sounds
unforgeable and is not. Trace the path, do not read the name.
</details>

<details>
<summary>Hint 3 — the patch-level delta, written properly</summary>

Compute months between `ro.build.version.security_patch` and today. More than about three is
reportable.

Write it as a count of missed bulletins, not as a date: *"The device's security patch level is
2021-12-01. As of the test date this is 56 months old, meaning approximately 56 monthly Android
Security Bulletins have not been applied."* A date makes the reader do arithmetic; a count of
bulletins makes the risk immediate.

Check `ro.vendor.build.security_patch` separately and report the **older** of the two. Here they
happen to match at `2021-12-01`; frequently they do not, and the vendor one is the real answer.
</details>

<details>
<summary>Hint 4 — I only have a stock device, so nothing is forged</summary>

Good. Run every step and record the honest values, then read this document's outputs as the
contrast. You have learned the more important half: **you cannot tell the two apart from the
property values.** The stock device and the rooted device print the same `green`, `1`, `locked`,
`release-keys`, `0`, `1`, `Enforcing`.

That is the finding. If reading the properties could distinguish them, none of chapters 37, 38, 50
or 67 would need to exist.
</details>

---

## Verification — did you actually do this?

Answer these from your own captured output, not from memory:

1. What is your device's `ro.build.fingerprint`, verbatim? (If you cannot paste it, you did not
   record it, and your report cannot identify the device under test.)
2. How many months old is the patch level, and which of the two patch properties gave the older
   answer?
3. For each of `verifiedbootstate`, `device_state` and `veritymode`: does the kernel command line
   agree with the property? If you could not read the command line, **which layer denied you** —
   DAC or MAC — and how do you know?
4. What SELinux context does `su -c id` report, and what does that context's existence tell you
   about the meaning of `getenforce` returning `Enforcing`?
5. Name the one signal in Step 8's table that root cannot forge, and say why it is different in kind
   rather than merely harder.

---

## Success criteria

- [ ] You have a single script that prints every posture signal, labelled, in a fixed order, taking
      a serial argument, and distinguishing "not set" from empty.
- [ ] You can state, for each signal, whether root can forge it — **and why**, by naming where the
      value lives at read time rather than by quoting this document.
- [ ] You have compared `/proc/cmdline` against the `ro.boot.*` properties, or established which
      layer prevented you and what that implies for an app trying the same thing.
- [ ] You can explain how `ro.boot.verifiedbootstate` gets from the bootloader into a Java `String`,
      naming at least four of the six stages (§4.5).
- [ ] You have written one paragraph of report-quality prose describing the patch posture as a
      **delta in months and a count of missed bulletins**, not as a date.
- [ ] You can name the one class of signal that root cannot forge, and explain that it is absent
      from this lab because obtaining it requires asking the TEE — which is
      [Lab 02](lab-02-vbmeta-and-verified-boot.md),
      [49 — KeyStore](../../49-KeyStore/README.md) and
      [50 — HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md).
- [ ] You can state, in one sentence, why a device reporting `green` is not evidence of anything.

---

## Going further

**1. Diff three devices.** Run your script against an emulator, a stock physical device and a rooted
one. The diff is a compact education in what rooting changes and what it does not. Real emulator
output for comparison, from an API 35 AVD:

```text
ro.product.model                = sdk_gphone16k_x86_64
ro.build.fingerprint            = google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys
ro.build.type                   = userdebug
ro.build.tags                   = dev-keys
ro.build.version.sdk            = 35
ro.build.version.security_patch = 2024-09-05
ro.boot.verifiedbootstate       = (not set)
ro.boot.flash.locked            = (not set)
ro.boot.vbmeta.device_state     = (not set)
ro.boot.veritymode              = enforcing
ro.debuggable                   = 1
ro.secure                       = 1
ro.kernel.qemu                  = 1
getenforce                      = Enforcing
```

Note the shape of the difference. The rooted phone lies by **setting the properties to the values a
good device would have**. The emulator does not lie at all — it **does not set them**, and
advertises itself with `dev-keys`, `userdebug`, `ro.debuggable=1` and `ro.kernel.qemu=1`. Those are
opposite failure modes, and a detection routine tuned for one is blind to the other. That asymmetry
is the whole subject of [39-EmulatorDetection](../../39-EmulatorDetection/).

**2. Read the vbmeta the properties are summarising.** `ro.boot.vbmeta.digest` is a hash of a
structure you can open. That is [Lab 02](lab-02-vbmeta-and-verified-boot.md), which takes the
forgery you found in Step 3 and proves it a third way — by hashing the boot partition and comparing
it against what vbmeta says it should be.

**3. Ask the hardware instead.** Everything in this lab is a claim from software. Generate a
hardware-backed key with an attestation challenge and read `verifiedBootState` out of the
certificate chain: [49 — KeyStore](../../49-KeyStore/README.md),
[50 — HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md). On this device the answer
is `Unverified`, and it took one API call to get an answer that nine `getprop`s could not.

**4. Write the finding.** Take your posture record and draft the environment section of a report:
device identity, patch delta, root state, and — critically — a sentence separating *what you
observed* from *what your instrument caused*. That discipline is what
[Lab 03](lab-03-integrity-gate-bypass.md) then builds a full finding on top of.
