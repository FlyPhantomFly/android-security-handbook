# 62 — Magisk · FAQ

Real questions, including the ones people are embarrassed to ask. Nothing here is too basic; every
single one of these has cost somebody a device or an afternoon.

---

### 1. Is rooting the same as jailbreaking?

They rhyme; they are not the same thing.

**Jailbreaking** an iPhone means defeating the code-signing and sandbox enforcement that Apple's
locked bootloader imposes, usually by exploiting a vulnerability, because Apple provides no supported
way to run unsigned code.

**Rooting** an Android device usually needs no exploit at all. Most Android devices ship with a
documented, vendor-supported way to unlock the bootloader — you enable a toggle in developer options
and run one `fastboot` command. What you get afterwards is a Unix superuser (UID 0) mechanism on a
device that never had one.

The practical differences that matter to you:

| | Jailbreak (iOS) | Root (Android) |
|---|---|---|
| Requires a vulnerability | Usually yes | Usually no |
| Vendor-supported path | No | Yes, on most devices |
| Destroys user data | No | **Yes** — unlocking wipes the device |
| Detectable by the platform | Yes | Yes, and reported by hardware attestation |
| Reversible | Restore firmware | Flash stock and re-lock, in that order |

"Rooted" also does not mean "can do anything". SELinux applies regardless of UID, and the TEE is a
different world entirely — see question 12.

---

### 2. Will this brick my phone?

It can. Honestly: probably not, if you follow lab 01 and use `fastboot boot` before `fastboot flash`.
But "probably not" is not "no", and the failure is not recoverable by software you own.

The realistic risk ladder, worst first:

| Risk | Likelihood | Recoverable? |
|---|---|---|
| Flashing an image for a different device model | Low if you check | Often **no** |
| Re-locking the bootloader with a patched boot image | Low | Frequently **no** |
| Flashing a boot image from a different build | Moderate — it is the classic mistake | Yes, reflash the correct one |
| Bootloop from a bad module | Moderate | Yes — safe mode, or `touch .../disable` over adb |
| Losing all your data at unlock | **Certain** | No, and that is by design |

The mitigations are all in [Lab 01](labs/lab-01-root-a-device.md): match `ro.build.fingerprint`
exactly, always `fastboot boot` before `fastboot flash`, keep the full factory image on the host, and
practise the recovery drills *before* you need them.

**Do not do this on a phone you need.** Buy a cheap second-hand Pixel for testing. This is not
optional advice dressed up as caution; it is the actual professional practice.

---

### 3. Do I have to unlock the bootloader? Can I root without it?

For Magisk, yes, you have to unlock. Magisk works by replacing the boot image, and a locked
bootloader verifies the boot image's signature and refuses to run a patched one.

Rooting *without* unlocking means exploiting a kernel or bootloader vulnerability to gain UID 0 —
which is real (it is how rooting worked before unlockable bootloaders were common) but is
version-specific, patched, and a research project rather than a procedure.

If your device's bootloader cannot be unlocked — carrier-locked units in several markets, recent
Huawei models — then this chapter's procedure does not apply to that device. Get a different one.

---

### 4. Unlocking wipes my data. Can I back it up first?

Back up whatever you can, but understand that a full backup of a modern Android device *without*
root is not really achievable: `adb backup` is deprecated and ignored by most apps, and app-private
data is exactly what you cannot reach without the privilege you are trying to obtain.

Copy your photos and documents off manually. Then accept that the device is being wiped, and treat
the wipe as the moment the device stops being a phone and starts being a test instrument.

The wipe is deliberate and it is a good security property. If unlocking did **not** wipe, then
physical possession of a locked, encrypted phone would be enough to unlock it, patch the boot image,
and read everything — which converts theft into full data extraction. Question 1's table lists it as
a difference from iOS; it is one of the places Android's model is stronger.

---

### 5. Can I un-root? Can I go back to stock and re-lock?

Yes, and the **order is the whole answer**:

1. Flash the complete stock factory image, every partition.
2. Boot it. Confirm it works.
3. Only then re-lock with `fastboot flashing lock`.

Re-locking **first**, or re-locking while a patched boot image is flashed, is one of the fastest ways
to permanently brick a device: the locked bootloader verifies the boot image, the patched image
fails, the device will not boot, and unlocking again requires a toggle in an OS you can no longer
reach.

Note also that re-locking wipes the device again, and that on devices with a one-time fuse (Samsung
KNOX being the standard example) un-rooting does not restore what the fuse disabled. The fuse is not
software.

---

### 6. Why does my banking app still detect root after I enabled DenyList?

Because DenyList does not hide root. It **retreats**: it removes Magisk's mounts from that process's
mount namespace so the filesystem looks untouched. Anything Magisk cannot unmount is still there.

Things DenyList does nothing about, all of which apps check:

- The Magisk Manager package being installed and visible (hide it separately).
- System properties — `ro.boot.verifiedbootstate` is still `orange`, because the bootloader really
  did report that.
- The loaded SELinux policy, which contains Magisk's domain.
- Hardware-backed attestation: a Play Integrity verdict, or the `RootOfTrust` extension in a key
  attestation certificate chain, both of which carry the real boot state signed inside the TEE.
- The *shape* of the namespace. Removing a mount is not the same as never having made one.

[Lab 03](labs/lab-03-denylist-investigation.md) has you measure every one of these on your own device
rather than take the list on trust. And see question 12 for the part that cannot be fixed at all.

---

### 7. What is the difference between DenyList, MagiskHide and Zygisk?

Three different things that people use interchangeably.

| Name | What it is | Status |
|---|---|---|
| **MagiskHide** | The older feature that unmounted Magisk's modifications in a target process, plus assorted property and process-name spoofing | **Removed** in Magisk 24. If a guide mentions it, the guide is out of date |
| **Zygisk** | A *mechanism*: loads a library into the zygote process and hooks the JNI functions zygote calls when forking an app, so module code can run inside every app process. It is an injection framework, not a hiding feature | Current, and the foundation LSPosed is built on |
| **DenyList** | A *list of processes* for which Magisk performs its unmount, implemented inside the Zygisk hook. Enabling it requires Zygisk to be on | Current |

The relationship in one sentence: **Zygisk is the injection point; DenyList is one thing done at that
injection point.** Ticking a box in DenyList without Zygisk enabled does nothing, which is why the
DenyList settings entry does not even appear until you turn Zygisk on.

---

### 8. I enabled DenyList and my Burp interception stopped working. What broke?

Nothing broke. You did two mutually exclusive things.

Your interception CA is installed as a Magisk module, which delivers it by bind-mounting a file into
`/system/etc/security/cacerts/`. DenyList removes Magisk's bind mounts from the target's namespace —
*all* of them, including that one. So the certificate is present for every process on the device
except the one you wanted to intercept.

Confirm it in one command:

```bash
# adb shell as root
PID=$(pidof -s com.example.target)
ls /system/etc/security/cacerts/ | wc -l                                        # global
nsenter --mount=/proc/$PID/ns/mnt -- ls /system/etc/security/cacerts/ | wc -l   # the app's view
```

Your options, none of them free: intercept without DenyList and deal with the root detection some
other way; hook the app's TLS verification directly instead of using the trust store; or supply the
certificate through a mount Magisk did not make, which is exactly what
[Lab 05](labs/lab-05-ctf-invisible-mount.md) is about.

---

### 9. Why does an OTA update break Magisk, and how do I take updates?

An OTA writes a new boot image. Yours was patched; the new one is not. On A/B devices the update is
written to the *inactive* slot and the device switches to it at reboot, so your patched image is
simply no longer the one being booted.

Two workable approaches:

1. **The simple one that always works.** Take the OTA, lose root, download the factory image for the
   new build, patch that build's boot image, and reflash. Ten minutes, no surprises.
2. **Magisk's "Install to Inactive Slot (After OTA)".** Download the OTA but do not reboot; use that
   option in the Magisk app to patch the newly-written slot before the switch. Read the install
   documentation for the Magisk version you are running first, because the details have changed
   across versions.

What does **not** work: reusing your old patched image. Boot images are build-specific.

---

### 10. Do I patch `boot.img` or `init_boot.img`?

Measure; do not guess.

```bash
# adb shell
ls -l /dev/block/by-name/ | grep -i init_boot
```

If an `init_boot` partition exists — typically Android 13+ GKI launches, Pixel 7 and later — the
generic ramdisk lives there and that is what you patch. Otherwise you patch `boot.img`. A small
number of older "system-as-root" devices have no ramdisk in `boot` at all and use the recovery
partition instead.

The Magisk app's home screen shows a **Ramdisk: Yes / No** line, which is the same question answered
for you. And `fastboot boot patched.img` costs nothing and answers it definitively: if the device
boots and `su` works, you patched the right thing.

---

### 11. Is a rooted device a finding on an engagement?

**No.** Your rooted device is your instrument. It is methodology, not a finding.

This confusion is common enough that this repository's own posture script has a flag for it:
`06-Android-Architecture/scripts/device-posture.sh --test-device` suppresses exactly this class of
result, and prints "YOUR OWN TEST DEVICE — methodology, not a finding" against the rows it would
otherwise report. Use it, and adopt the same discipline in your notes: a control you deliberately
removed in order to test is not a weakness you discovered.

What *is* a finding, in this area:

- The application does not detect root at all, in a threat model where it should.
- It detects root but only client-side, and the verdict is trusted by the server.
- It detects root and blocks, but the block is a single hookable boolean.
- The **client's** production or field devices are rooted, unlocked, or shipping `userdebug` builds.
- The device you were given by the client is unlocked, or `ro.debuggable` is 1 on a production build.

And what to write in the methodology section: which device, which fingerprint, which Magisk version,
which modules, which hiding measures were applied, and what was verified about what the app could
see. [Lab 01 Step 10](labs/lab-01-root-a-device.md#step-10--write-the-device-record) produces exactly
that record, and it exists so that a client's engineer cannot dismiss your results.

---

### 12. Can Magisk hide root from Play Integrity or SafetyNet?

No, and be careful how you phrase this in a report, because the client's engineers know the answer.

SafetyNet's early "basic integrity" checks were largely software-side and property-based, which is
why property spoofing worked in that era. That era ended. The modern path is hardware-backed: the
device's real verified-boot state is signed **inside the TEE**, which is a different execution
environment from the Linux kernel that Magisk operates in, and the verdict is computed on **Google's
servers**, which you do not control.

Nothing you do in Linux userspace changes what the TEE signed, and nothing you do on the device
changes what a server concludes. `resetprop`, DenyList, hiding the Manager, a randomised package
name — none of them touch that path.

The productive move when you meet a hard attestation gate is to say so, in writing, and negotiate:
an older device without hardware attestation, a client-provided build with the check disabled, or a
scope exception. A tester who discovers on day one of a two-day engagement that hiding will not work
has made a scoping error, not a technical one.

---

### 13. Is Magisk malware? My antivirus flagged it.

Magisk is open-source software (GPL-3.0) whose purpose is to give a device's owner root on their own
device. That is legitimate, and it is also exactly what a rooting trojan does, so signature-based
scanners flag it. Both facts are true at once.

The care you should take is about **provenance and modules**, not about Magisk:

- Download the APK from the official GitHub releases page. Not from an APK mirror, not from a forum
  attachment. You are about to give this binary permanent boot-time control of the device.
- Treat every **module** as untrusted root code — see question 14.
- Never put Magisk on a device that holds real accounts, and never on a client's device.

---

### 14. Are Magisk modules safe to install?

Assume no, until you have read it.

There is **no code signing, no review, no permission model, no sandbox and no revocation** for Magisk
modules. Installing one gives its author a root shell that runs at every boot, at `post-fs-data`,
before zygote, before any application and before anything that could log it.

The realistic threat is not an obviously hostile module; it is a popular, genuinely useful module
changing hands, or its author's account being compromised, and version 4.3 containing eleven lines
that 4.2 did not.

Read `customize.sh`, `post-fs-data.sh`, `service.sh`, `boot-completed.sh`, `sepolicy.rule` and
everything under `system/` before you install anything.
[`scripts/audit-magisk-module.sh`](scripts/audit-magisk-module.sh) does the mechanical part, and
[Lab 04](labs/lab-04-module-audit.md) teaches the judgement part, which no script can do.

---

### 15. Magisk, KernelSU or APatch — which should I use?

Magisk, unless you have a specific reason not to. It has by far the widest device support, the
largest ecosystem, and the most documentation, and everything in this chapter assumes it.

The reason to know about the others is detection. Magisk's privileged logic lives in **userspace**,
so it produces userspace artefacts — mounts, a daemon, a socket, a patched policy — which another
userspace process can in principle observe. KernelSU and APatch move that logic into the **kernel**,
so the mounts are never applied to a non-allowlisted process's namespace and there is nothing for the
app to see. That is a genuine detection advantage.

It is not a silver bullet. It requires a compatible kernel, it narrows your device options
considerably, and it changes **nothing** about hardware-backed attestation. Treat it as another entry
in the cost table when Magisk-based hiding fails, not as a magic answer.

---

### 16. Can I just use an emulator? Do I need a physical device?

For a lot of this chapter, an emulator is fine — and if you do not yet have a device you can afford
to destroy, it is the right choice.

| Setup | What you get | What you do not |
|---|---|---|
| AVD with a Google **APIs** image | `adb root`, writable `/system`, enough privilege to explore | Not Magisk. No `magiskd`, no modules, no DenyList, no Zygisk |
| AVD with a Magisk-patched ramdisk (community tooling does this) | Real Magisk: modules, DenyList, Zygisk, mount namespaces. **Labs 02–05 all work** | No bootloader, no `fastboot`, no AVB — so lab 01's actual subject is only simulated |
| Physical device | Everything, including what a bootloop feels like | Costs money |

The honest recommendation: do labs 02–05 on a Magisk-patched AVD now, and buy a cheap second-hand
Pixel before you take on a real engagement. Apps also behave differently on emulators — some detect
them and take a different code path entirely — so a finding produced only on an emulator is a finding
a client can question.

---

### 17. I am root, but a command fails with "Permission denied". Why?

Almost certainly SELinux. Being UID 0 does not exempt you from mandatory access control: a root
process in a restrictive domain can be less capable than an unprivileged process in a permissive one.

```bash
# adb shell as root — the three-command diagnosis
id -Z                      # what domain am I in?
getenforce                 # Enforcing or Permissive?
dmesg | grep -i avc | tail # the denial itself, which names source, target, class and permission
```

The denial line is the answer written out: it tells you the source domain, the target type, the
object class and the permission that was refused, which is exactly the shape of a `magiskpolicy`
rule:

```bash
# adb shell as root
magiskpolicy --live "allow SOURCE TARGET file { read open getattr }"
```

---

### 18. Can I just run `setenforce 0` instead?

You can. Do not.

Two costs. First, it disables enforcement device-wide, which grants far more than the one thing you
needed, persistently. Second and more important for your work: **a permissive device is a different
device.** Applications take different code paths, some read `getenforce` directly and change
behaviour, and any finding you produce is open to the objection that it only reproduces with SELinux
disabled. That objection is fair and it will be made.

Targeted `magiskpolicy --live` rules, derived from denials you actually observed, keep the device in
`Enforcing` and keep your results defensible.

---

### 19. Do I need root for mobile pentesting at all?

Not for everything, and it is worth knowing where the line is.

**Without root you can still:** decompile and read the APK; analyse the manifest and exported
components; intercept traffic for apps that trust user CAs or that you have repackaged; test
`debuggable` builds through `run-as`; attack the server-side API, which is usually where the real
findings are; and do all of the static analysis in this repository.

**Root buys you:** reading another app's private data; running `frida-server` against arbitrary
processes; installing a system CA so that ordinary apps are interceptable without repackaging;
reading system-owned paths; and instrumenting the framework itself.

It is the difference between examining an app from the outside and standing inside it. Plenty of good
findings come from outside. But a scope that requires runtime instrumentation and a device that
cannot be rooted is a scoping problem to raise before day one, not to discover on it.

---

### 20. What is the difference between `fastboot boot` and `fastboot flash boot`?

`fastboot boot image.img` downloads the image into RAM and boots it **once**. Nothing on the device
is written. Power-cycle and you are back on the stock image.

`fastboot flash boot image.img` writes the image to the boot partition **permanently**.

Always test with `boot` before you `flash`. It is the single most valuable habit in this chapter, and
it converts "I bricked my phone" into "that image was wrong, let me get the right one". Some OEMs
disable `fastboot boot`; on those devices you have no free test, and you should have the full factory
image downloaded before you flash anything.

---

### 21. My device bootloops after installing a module. What do I do?

In this order, and you should have practised all three before you needed them
([Lab 01 Step 9](labs/lab-01-root-a-device.md#step-9--recovery-drills-do-these-while-nothing-is-wrong)):

1. **Safe mode.** Power off completely, power on, and hold **Volume Down** through the boot
   animation. Magisk disables all modules for that boot.
2. **adb.** A device that never reaches the launcher often still brings up `adb`:
   ```bash
   adb wait-for-device && adb shell "su -c 'touch /data/adb/modules/*/disable'" && adb reboot
   ```
3. **Remove the offender:** `touch /data/adb/modules/<id>/remove` and reboot.
4. **Reflash the stock boot image**, then start again.

The usual cause is a blocking wait in `post-fs-data.sh` — that stage stops the boot, so waiting there
for something the framework provides is a deadlock. Put waits in `service.sh`, and bound them.

---

### 22. Does root let me read another app's data, or the KeyStore?

Private data, yes. Hardware-backed keys, no.

With UID 0 and a permissive-enough SELinux context you can read any app's `/data/data/<pkg>`
directory: SharedPreferences, SQLite databases, cached tokens, everything. That is a large part of
why root is worth having.

But a key generated inside the TEE, or in a secure element with `setIsStrongBoxBacked(true)`, never
leaves that hardware. You can *use* it — ask the KeyStore to sign or decrypt with it, which is often
enough for what you need — but you cannot extract it. Root is Linux UID 0; the TEE is a different
world. See [49-KeyStore](../49-KeyStore/README.md) and 50-HardwareBackedSecurity.

The same boundary explains question 12: what you cannot reach, you cannot forge.
