# 06 — Android Architecture · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. Everyone draws the "Android stack" diagram with five boxes. Is that actually useful?**

Only partly. The layer diagram tells you what talks to what, which is worth knowing. But it does not
tell you where the *security boundaries* are, and that is what you actually need.

The more useful framing is a chain of **trust transitions**: fuses → bootloader → vbmeta →
dm-verity → init → Zygote → app. Each downward step is an irreversible privilege reduction. Nearly
every platform vulnerability is either "a step did not reduce as much as it claimed" or "a request
back upward was not properly authorised".

---

**2. What is `init`, really?**

PID 1. The first userspace process the kernel starts. It parses `.rc` files, starts and supervises
every long-lived service, and runs the property service.

The practical consequence: every persistent process on the device is either started by `init` or
forked from something `init` started. If you want to know what a daemon is allowed to do, find its
`init` entry — it declares the user, groups, capabilities and SELinux domain in about five lines.

---

**3. Why does Android fork app processes from Zygote instead of just starting them?**

Because starting a fresh process would mean loading and initialising thousands of framework classes
every single time. Zygote loads them **once**, then `fork()`s. The child inherits everything
copy-on-write, so framework memory is shared across every app rather than duplicated.

That is why Android app startup is fast on modest hardware, and it is one of the genuinely clever
pieces of the platform's design.

---

**4. I keep reading that Zygote "weakens ASLR". How badly?**

`fork()` produces a child with the *same* address-space layout as the parent. Because apps are forked
rather than `exec`ed, every app on the device has the framework and its shared libraries at identical
addresses until the next reboot. An address leaked from one process is immediately useful against
another.

How much it matters depends entirely on what you are doing. For **native exploitation** it is
significant — it converts per-process randomisation into per-boot randomisation. For **app-layer
testing** it is essentially irrelevant. It is a deliberate trade for startup speed and memory sharing,
not an oversight.

---

**5. What exactly builds the app sandbox?**

One function: `SpecializeCommon()` in
`frameworks/base/core/jni/com_android_internal_os_Zygote.cpp`. It runs in the child immediately after
the fork, and in order it sets resource limits, calls `setgroups()` with the supplementary GIDs, drops
to the app's UID and GID, calls `capset()` to drop capabilities, sets `PR_SET_NO_NEW_PRIVS`, installs
the seccomp-bpf filter, sets the SELinux context, sets the process name, and creates the app's mount
namespace.

The ordering matters: capabilities are dropped and `NO_NEW_PRIVS` is set **before** any application
code runs, so privilege cannot be regained.

If you read one function in AOSP this year, make it that one.

---

**6. How do I check that an app's sandbox is actually intact?**

```bash
PID=$(adb shell pidof -s com.example.target)
adb shell "cat /proc/$PID/status | grep -E 'Uid|Gid|Groups|CapEff|Seccomp|NoNewPrivs'"
adb shell "cat /proc/$PID/attr/current"
```

Expect a UID of 10000+, `CapEff` of all zeros, `Seccomp: 2`, `NoNewPrivs: 1`, and an
`untrusted_app_XX` SELinux context with MCS categories.

Anything non-empty in `CapEff` on an app process is highly anomalous. `Seccomp: 0` usually means the
process was not created by Zygote in the normal way.

---

**7. What does `ro.build.tags=test-keys` mean, and why do you keep calling it critical?**

It means the system image was signed with the **public AOSP test keys**, which are published in the
source tree at `build/make/target/product/security/`.

Because anyone can use them, anyone can build an APK signed with the platform key. That APK receives
every `signature`-level permission — including `INSTALL_PACKAGES` and `INJECT_EVENTS` — and can
declare `sharedUserId="android.uid.system"`. That is a complete bypass of the permission model from a
single build-configuration mistake.

It is uncommon on phones and genuinely common on set-top boxes, industrial handhelds and IoT devices.
Check it on every device assessment.

---

**8. Why can't I just edit a file in `/system` on a normal device?**

dm-verity. The partition's blocks are hashed into a Merkle tree whose root hash is signed, and **every
read verifies that block up the tree**. Modification is detected the moment the block is read.

The granularity is the whole partition — you cannot change one byte. Disabling verity requires an
unlocked bootloader. This is precisely why Magisk uses an overlay/mount-namespace approach instead of
modifying the underlying blocks: it never touches the verified partition at all.

---

**9. Is `/data` protected by dm-verity too?**

No, and this catches people. `userdata` is **encrypted** (File-Based Encryption) but it is **not**
integrity-protected. Anyone who can write it — any root process, or an attacker with an offline write
primitive on an unlocked device — can modify app data without any verity failure.

`fs-verity` provides per-file integrity for specific things on `/data`, notably installed APKs, but it
is opt-in per file, not blanket protection.

Also worth knowing: `/persist` is frequently **neither** verified nor encrypted, is writable by vendor
processes, and on some devices holds security-relevant material.

---

**10. Why can SELinux block a property write but not a property read?**

Because the two paths are completely different, and this is one of the more elegant details in the
platform.

**Reads** `mmap` the property area under `/dev/__properties__` directly from libc and walk a prefix
trie. There is no IPC, no syscall to a service, nothing to intercept — so there is nothing for SELinux
to mediate.

**Writes** connect over a socket to `property_service` inside `init`, which calls `CheckPermissions()`
and consults the SELinux `property_service:set` permission using the property's context from
`property_contexts`. That is a mediated operation, so it can be denied.

```bash
getprop -Z ro.debuggable    # shows the property's SELinux context
```

---

**11. Root detection reads properties. If I hook the Java API, am I done?**

No, and this is the most common incomplete bypass. There are **three** routes an app can use to read a
property:

1. `android.os.SystemProperties.get()` in Java (a `@hide` class, reached by reflection)
2. `__system_property_get()` in libc, from native code
3. Shelling out to `/system/bin/getprop`

Hooking only the first is why a "working" Frida script suddenly fails against an app that added a
native check. A complete bypass covers all three. See
[37-RootDetection](../37-RootDetection/README.md).

---

**12. What is Project Mainline and why does it change how I assess patch level?**

Certain OS components — ART, Conscrypt (TLS), media and codecs, the DNS resolver, the network stack,
Bluetooth, Wi-Fi, the permission controller — ship as APEX modules or APKs that update **through
Google Play**, independently of the OEM.

The consequence: `ro.build.version.security_patch` alone is no longer a complete statement about a
device's patch status. You must also record the Google Play system update level, which governs the
Mainline components.

Notice which components were chosen: they are precisely the historic *remote* attack surfaces. That
was not an accident.

---

**13. So does Mainline mean Android is patched now?**

For the modularised components, largely yes — fixes reach devices in days to weeks rather than never.

For everything else, no. Vendor HALs, kernel drivers, OEM system apps and vendor daemons are still
entirely dependent on the OEM's update pipeline, and that pipeline still frequently does not deliver.

The practical research consequence: an exploit for a Mainline component has a short useful life; an
exploit for a vendor component may remain viable for years.

---

**14. I'm assessing an OEM device. Where should I actually look?**

Not AOSP. It is the most scrutinised code in the ecosystem and you are unlikely to out-research
Project Zero on it in a week.

Look at what the OEM added: `/vendor` and `/odm` daemons and HALs, pre-installed privileged apps in
`/system/priv-app`, the `privapp-permissions-*.xml` grants, custom SELinux policy, and init `.rc`
service definitions.

The single highest-value check is the init `.rc` audit — it shows every service's user, capabilities
and SELinux domain in a form you can grep:

```bash
grep -rhA10 '^service ' /system/etc/init/ /vendor/etc/init/ \
  | grep -E '^service |user |group |capabilities |seclabel |socket '
```

A service with **no `user` line runs as root**.

---

**15. What's wrong with a `socket ... 0666` line in an init file?**

A UNIX socket with mode `0666` is readable and writable by **every app on the device**. It is an IPC
endpoint sitting entirely outside the framework's permission model — no permission check, no Binder
UID verification, nothing.

If the daemon behind it performs privileged operations on request, any app can ask it to. This is a
recurring and high-value finding on OEM devices. See [24-IPC](../24-IPC/README.md).

---

**16. My test device has an unlocked bootloader and permissive SELinux. Do I report that?**

**No** — you did that. It is methodology, and it belongs in the Test Environment section of the report
alongside your tool versions.

It becomes a finding only when you observe it on a device **as shipped to users**. Confusing the two
damages a report's credibility faster than almost anything else, and experienced clients notice
immediately.

The `device-posture.sh` script in this chapter has a `--test-device` flag for exactly this reason.

---

**17. What is the difference between recovery mode and fastboot mode? I mix them up constantly.**

They are two different programs in two different states.

**Recovery** is a booted minimal Linux with a small Android userspace, running from the recovery
ramdisk. It speaks `adb` (sideload only, on stock recovery) and does things like applying OTA packages
and factory resets.

**Fastboot** is the bootloader itself — no kernel, no Linux. It speaks the fastboot USB protocol and
does unlocking, flashing partitions, and reading variables.

`fastbootd` muddies this: it is a *userspace* fastboot implementation living in the recovery ramdisk,
needed because the bootloader cannot resize logical partitions on devices with dynamic partitions.

```bash
adb reboot recovery
adb reboot bootloader     # real fastboot
adb reboot fastboot       # fastbootd
```

---

**18. Why do you keep saying `fastboot boot` instead of `fastboot flash`?**

Because `fastboot boot` loads an image into RAM and boots it **once**. If the image is wrong, you
power-cycle and the device returns to exactly its previous state.

`fastboot flash` persists it. A bad image means a device that will not boot, and possibly a full
factory-image restore.

Test with `boot`, then flash only when you know it works. This one habit will save you a device sooner
or later.

---

**19. What is `super` and why does `fastboot flash system` fail on modern devices?**

`super` is one large physical partition containing **logical partitions** — `system`, `vendor`,
`product`, `odm` — carved out of it, described by metadata that first-stage `init` reads with `liblp`.
It exists because fixed partition sizes waste space, especially with A/B doubling everything.

`fastboot flash system` fails from the bootloader because the bootloader's own fastboot cannot resize
logical partitions. You need `fastbootd` — userspace fastboot — reached with `adb reboot fastboot`.

```bash
lpdump                      # the logical layout (root)
ls -l /dev/block/mapper/    # logical partitions as device-mapper devices
```

---

**20. What is the anti-rollback index, and how do I avoid bricking a research device with it?**

AVB includes a monotonic counter stored in hardware fuses. Once a device has booted an image with
rollback index N, the bootloader **permanently refuses** images with a lower index.

It is a good security feature — you cannot downgrade a patched device back to a vulnerable build. It
is also an excellent way to make a research device useless if you flash a newer image and then want to
go back.

Check before flashing:

```bash
fastboot getvar all | grep -i rollback
python3 external/avb/avbtool.py info_image --image vbmeta.img | grep -i rollback
```

---

**21. `ps` shows a lot of processes running as root. Is that bad?**

Some are expected — `init`, `ueventd`, `logd`, `vold`, `servicemanager`, `netd`, `installd`, the
Zygotes. A long list of *vendor* daemons as root is worth reading carefully.

For each one, find its init entry and read its actual privilege budget. A vendor daemon running as
root with `SYS_ADMIN` and a world-accessible socket is a realistic finding, and far more likely to be
productive than hunting kernel bugs.

`scripts/layer-census.sh` in this chapter does this triage automatically.

---

**22. What is `seinfo` and where does an app's SELinux domain come from?**

`seinfo` is a string that `PackageManagerService` computes for a package (based on its signature,
whether it is privileged, its `targetSdk`, and so on) and passes to Zygote in the fork request.
`SpecializeCommon()` then calls `selinux_android_setcontext()` with it, and the mapping in
`seapp_contexts` determines the resulting domain — `untrusted_app`, `untrusted_app_29`, `priv_app`,
`platform_app`, `isolated_app`, and so on.

The MCS categories appended to the domain are what give per-app isolation *within* a shared domain.
See [22-SELinux](../22-SELinux/README.md).

---

**23. Why is `system_server` such an important target?**

Because it runs as UID 1000 with a very large set of permissions, hosts most of the framework's
services, and is reachable over Binder by **every app on the device** by design.

The characteristic vulnerability is the **confused deputy**: `system_server` performs a privileged
action on an app's behalf without properly checking that the app was entitled to request it.
this is a bug in `system_server`, not in Binder — Binder faithfully delivers an unspoofable caller UID;
the service has to check it.

---

**24. I have limited time on an unfamiliar device. What are the first five commands?**

```bash
adb shell getprop ro.build.fingerprint
adb shell 'getprop ro.build.tags; getprop ro.debuggable; getprop ro.secure'
adb shell 'getprop ro.boot.verifiedbootstate; getenforce'
adb shell getprop ro.build.version.security_patch
adb shell 'ps -A -Z | awk "{print \$1}" | sed "s/:s0.*//" | sort | uniq -c | sort -rn | head'
```

That gives you: which build this is, whether the build configuration is sane, whether the boot chain
is intact, how stale it is, and what the privilege distribution looks like. Then run
`scripts/device-posture.sh` for the full version with verdicts.
