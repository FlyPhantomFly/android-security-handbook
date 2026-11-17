# Lab 01 — Mapping the Sandbox on a Real Device

**Difficulty:** Beginner
**Time:** 45–60 minutes
**Prerequisites:** [Chapter 21 §3.1–3.6](../README.md#3-deep-internal-working), a device or emulator
with `adb`. Root is helpful for two optional steps and is called out where needed.

---

## Objective

Take one running application and reconstruct its **entire privilege** from the kernel's own records:
its UID and the arithmetic behind it, every supplementary group it holds, its capability sets, its
seccomp state, its `no_new_privs` state, and its SELinux context including the MCS categories. By the
end you will be able to look at `/proc/<pid>/status` for any app and say precisely what that process
can and cannot do, and *which mechanism* stops each thing.

## Why this matters

Three practical reasons.

First, this is the ground truth. Framework APIs, `dumpsys` output and decompiled code all describe
what the app *intends*. `/proc/<pid>/status` describes what the kernel will actually enforce. When
those two disagree, the kernel wins, and you want to be the person in the room who checked.

Second, almost every methodological error in mobile testing is an identity error — testing from the
wrong context and generalising. This lab makes the difference between `adb shell` (UID 2000, no
seccomp filter, non-empty capability bounding set) and an app (UID 10xxx, `Seccomp: 2`, all-zero
capabilities) something you have *seen*, not something you have read.

Third, it makes the seven enforcement layers concrete. Every one of them shows up as a line of text in
a file you can `cat`.

> **Definition — `/proc`**
> `/proc` is a *pseudo-filesystem*: it contains no data on disk. Reading a file under `/proc` causes
> the kernel to generate the contents on the spot from its own in-memory structures. `/proc/<pid>/status`
> is therefore not a report *about* a process; it is the process's kernel state, rendered as text at the
> moment you read it.

---

## Setup

```bash
# host
adb devices
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.build.type          # "user" | "userdebug" | "eng"
adb shell getprop ro.debuggable          # 1 on userdebug/eng — this changes run-as behaviour
```

Record all five. `ro.build.type` and `ro.debuggable` change what this lab can show you, and every
finding you ever write should state which kind of build it came from.

Pick a target. Any third-party app will do; this lab uses `com.example.torch` as a placeholder.

```bash
# adb shell
pm list packages -3            # third-party packages
PKG=com.example.torch
```

Launch the app and leave it in the foreground, so a process actually exists.

---

## Steps

### Step 1 — Establish who *you* are before you look at anything else

```bash
# adb shell
id
# uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),... context=u:r:shell:s0
```

Write the output down. Every subsequent command in this lab runs with that identity unless you say
otherwise.

**Question 1.** You are UID 2000, in the SELinux domain `shell`, and you hold a list of supplementary
groups. Name two concrete things that identity lets you do that an installed application cannot. What
does that imply about any conclusion of the form "an app can do X" that you reach from this shell?

### Step 2 — Find the UID three different ways

```bash
# adb shell
pm list packages -U | grep $PKG
# package:com.example.torch uid:10388

dumpsys package $PKG | grep -E 'userId=|gids=|dataDir=|flags=|sharedUser'

pidof $PKG
ps -A -o USER,UID,PID,NAME | grep $PKG
```

And, if you have root, the authoritative file:

```bash
# adb shell as root
su -c "grep $PKG /data/system/packages.list"
# com.example.torch 10388 0 /data/user/0/com.example.torch default:targetSdkVersion=34 3003,9997 0 1
```

Fill this in:

| Field | Value |
|---|---|
| UID | |
| userId (`uid / 100000`) | |
| appId (`uid % 100000`) | |
| Unix name (`u<userId>_a<appId-10000>`) | |
| Data directory | |
| `packages.list` field 3 (debuggable) | |
| `packages.list` field 6 (GIDs) | |
| `sharedUserId` present? | |

**Question 2.** Your device probably also has a work profile or a second user, or could have. If the
same package were installed for Android user 10, what would its UID be, where would its data live, and
would the two installations be able to read each other's files?

### Step 3 — Read the kernel's record

```bash
# adb shell
PID=$(pidof $PKG)
cat /proc/$PID/status
```

That is a lot of output. Pull out the security-relevant lines:

```bash
# adb shell
grep -E '^(Name|Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb|Seccomp|Seccomp_filters|NoNewPrivs)' /proc/$PID/status
```

Record every line. Then compare against your own shell:

```bash
# adb shell
grep -E '^(Uid|Gid|Groups|CapBnd|Seccomp|NoNewPrivs)' /proc/$$/status
```

**Question 3.** `Uid:` has four numbers. What are they, and why would it ever be useful for them to
differ? Do they differ on the app?

### Step 4 — Decode the `Groups:` line

This is the step people skip, and it is the most interesting line in the file.

```bash
# adb shell
grep Groups /proc/$PID/status
# Groups:	3003 9997 20388 50388
```

Map each number against the table in [§3.9](../README.md#39-network-isolation--internet-as-a-group-membership)
and [§3.1](../README.md#31-the-uid-what-it-is-where-the-numbers-come-from-and-what-they-mean).

| GID | Name | What it confers |
|---|---|---|
| 3003 | `AID_INET` | **`AF_INET`/`AF_INET6` socket creation — this *is* the `INTERNET` permission** |
| 3004 | `AID_NET_RAW` | `SOCK_RAW` |
| 3009 | `AID_READPROC` | Reading other processes' `/proc` entries |
| 9997 | `AID_EVERYBODY` | A group every app is in |
| 50000 + appId | Per-app "shared GID" used for some storage paths | |

**Question 4.** `INTERNET` is declared in the manifest like any other permission, but it does not
appear anywhere in a runtime permission list and cannot be revoked in Settings. Explain, precisely,
where it *is* recorded and which component put it there. Then explain why hooking `java.net.Socket`
with Frida cannot grant it to an app that lacks it.

Verify your reasoning empirically if you have two apps to hand:

```bash
# adb shell — an app WITHOUT INTERNET has no 3003
grep Groups /proc/$(pidof com.example.nointernet)/status
```

### Step 5 — Confirm the capability sets are empty

```bash
# adb shell
grep -E '^Cap' /proc/$PID/status
# CapInh:	0000000000000000
# CapPrm:	0000000000000000
# CapEff:	0000000000000000
# CapBnd:	0000000000000000
# CapAmb:	0000000000000000
```

All five must be all zeros. Compare with a system process:

```bash
# adb shell as root
grep -E '^Cap' /proc/$(pidof system_server)/status
```

**Question 5.** Of the five sets, `CapBnd` is the one that makes the guarantee. Say what the bounding
set means, and then name the *other two* independent mechanisms that would still prevent an app from
escalating via a setuid binary even if `CapBnd` were non-empty. Verify one of them:

```bash
# adb shell
mount | grep -E ' /data | /storage '
```

### Step 6 — Confirm seccomp

```bash
# adb shell
grep -E '^(Seccomp|Seccomp_filters|NoNewPrivs)' /proc/$PID/status
# Seccomp:	2
# Seccomp_filters:	1
# NoNewPrivs:	1
```

`Seccomp: 2` is `SECCOMP_MODE_FILTER`. `NoNewPrivs: 1` is the `PR_SET_NO_NEW_PRIVS` flag, which is a
precondition for an unprivileged process installing a filter and is itself irreversible.

**Question 6.** Your shell showed `Seccomp: 0` and `NoNewPrivs: 0` in step 3. Explain in one sentence
why that single difference invalidates any experiment of the form "I tried it in `adb shell` and it
worked, so an app can do it."

Optional, root only — watch a denial happen:

```bash
# adb shell as root
dmesg -w | grep -i seccomp
# audit: type=1326 audit(...): auid=... uid=10388 ... comm="torch" ... syscall=224 ...
```

`syscall=224` is a number, not a name. Map it with the kernel's syscall table for your architecture
(`include/uapi/asm-generic/unistd.h`, or `arch/arm64/include/asm/unistd32.h` for the 32-bit compat
table) or with `ausyscall` on a host that has the `auditd` tools.

### Step 7 — Read the SELinux context

```bash
# adb shell
cat /proc/$PID/attr/current
# u:r:untrusted_app_34:s0:c288,c256,c512,c768

ps -A -Z | grep $PKG
```

Break the context into its four parts:

```
u:r:untrusted_app_34:s0:c288,c256,c512,c768
│  │  │                │  │
│  │  │                │  └── MCS categories — derived from appId and userId
│  │  │                └───── sensitivity level (always s0 for apps)
│  │  └────────────────────── TYPE / domain
│  └───────────────────────── role
└──────────────────────────── SELinux user
```

Now look at the *file* labels:

```bash
# adb shell as root
ls -ldZ /data/data/$PKG
ls -lZ  /data/data/$PKG/shared_prefs/ 2>/dev/null
```

**Question 7.** Two different third-party apps both run in the domain `untrusted_app_34`. Type
enforcement alone therefore cannot distinguish them. What *does* separate them, and what would happen
if two apps ended up with identical category sets?

Compare against a system app and an isolated process if one is running:

```bash
# adb shell
ps -A -Z | grep -E 'untrusted_app|priv_app|platform_app|system_app|isolated_app|sdk_sandbox'
```

### Step 8 — Prove the boundary from the filesystem side

Pick a second installed app, `$OTHER`.

```bash
# adb shell
ls -la /data/data/$OTHER
# ls: /data/data/com.other.app: Permission denied

ls -la /data/app/*/${OTHER}*/base.apk 2>/dev/null
pm path $OTHER
```

Then read the other app's **APK**:

```bash
# adb shell
APK=$(pm path $OTHER | head -1 | sed 's/package://')
ls -l $APK
# -rw-r--r-- 1 system system 8421376 ... base.apk
head -c 4 $APK | xxd
```

**Question 8.** Your shell cannot list another app's data directory but *can* read its APK. Explain
both results from the mode bits and ownership you just observed, and state the consequence for any
secret compiled into an APK.

### Step 9 — The same experiment from inside the app

Everything so far ran as UID 2000. Now run the identical probe as the app itself. Two ways:

**If the app is debuggable:**

```bash
# adb shell
run-as $PKG id
run-as $PKG cat /proc/self/status | grep -E '^(Uid|Gid|Groups|Cap|Seccomp|NoNewPrivs)'
run-as $PKG cat /proc/self/attr/current
run-as $PKG ls -la /data/data/$PKG
run-as $PKG ls -la /data/data/$OTHER
```

**If it is not**, use the chapter's inspection script, which does the whole of steps 3–7 in one call
and annotates the output:

```bash
# host
adb push ../scripts/sandbox-inspect.sh /data/local/tmp/
adb shell sh /data/local/tmp/sandbox-inspect.sh $PKG
```

**Question 9.** `run-as` printed `context=u:r:runas_app:s0:c288,...` rather than
`u:r:untrusted_app_34:...`, and its `Seccomp:` line does not match the app's. Given that, is `run-as`
a faithful reproduction of the app's sandbox? What is it good for, and what should you not conclude
from it?

### Step 10 — Build the map

Produce a single table for at least five processes on the device: your shell, two third-party apps, one
system app, and `system_server`.

| Process | UID | appId | Groups | CapBnd | Seccomp | SELinux context |
|---|---|---|---|---|---|---|
| `adb shell` | 2000 | — | | | 0 | `u:r:shell:s0` |
| app A | | | | | | |
| app B | | | | | | |
| a system app | | | | | | |
| `system_server` | 1000 | — | | | | |

**Question 10.** For each of the seven enforcement layers named in §1.3 — UID/DAC, SELinux MAC, seccomp,
capabilities, isolated/SDK sandboxing, network GIDs, package visibility — point at the specific line of
evidence in your table that demonstrates it, or say why that layer is not visible here.

---

## Hints

<details>
<summary>Hint 1 — <code>pidof</code> returns nothing</summary>

The app is not running, or it is running under a different process name. Launch it, then:

```bash
# adb shell
ps -A -o USER,PID,NAME | grep -i torch
```

Apps that declare `android:process` have processes named `com.example.torch:worker`. `pidof
com.example.torch` will not match those. Note down every process the package owns — a package can have
several, and they may have *different* UIDs if any of them is isolated.
</details>

<details>
<summary>Hint 2 — <code>cat /proc/&lt;pid&gt;/status</code> says Permission denied</summary>

From Android 10 the `/proc` filesystem is hardened so a process sees only its own entries. Your `adb
shell` (UID 2000) normally still has enough privilege via `AID_READPROC`; if it does not on your build,
use `su`, or read `/proc/self/status` from inside the app with `run-as` or Frida instead.

This restriction is itself a lab result:an *app* cannot read another app's
`/proc/<pid>/status` at all on a modern device.
</details>

<details>
<summary>Hint 3 — the Groups line has numbers not in any table</summary>

Two patterns are normal and undocumented-looking:

- `20000 + appId` and `50000 + appId` — per-app GIDs used for external-storage paths and for
  `sharedUserId` accounting. They are derived, not assigned from a fixed table.
- Numbers in the 3000s that you do not recognise: check
  `system/core/libcutils/include/private/android_filesystem_config.h` for the AOSP branch matching
  your device. The list has grown over releases.
</details>

<details>
<summary>Hint 4 — <code>run-as</code> says "package not debuggable"</summary>

That is field 3 of `packages.list` being `0`. It is the expected result on a release build and is not
a problem — it means step 9's first path is unavailable and you should use the script instead.

Do **not** solve this by repackaging the app with `android:debuggable="true"` for this lab. It works,
but it changes the signature, and the point of this lab is to observe an unmodified app.
</details>

<details>
<summary>Hint 5 — MCS categories look random</summary>

They are derived, but from more than just the appId on modern releases — there is per-install
randomness precisely so that a recycled appId does not silently inherit the previous app's category
set. Do not try to reverse the derivation. What matters is that they *differ* between apps and that
the app's process context and its file labels *match each other*.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** UID 2000 in the `shell` domain can, among other things: read and write `/data/local/tmp` (which
no app can), read many `/proc` entries belonging to other processes via `AID_READPROC`, start
components and query providers that policy blocks for `untrusted_app`, run `dumpsys` and `pm` and
`am`, and use `run-as`. It also has **no seccomp filter** and a **non-empty capability bounding set**.

The implication is the one this repository repeats everywhere: an experiment run from `adb shell`
answers the question "can UID 2000 in the `shell` domain do this?" It does not answer "can an app the
user installs do this?" Those are different questions with different answers, and only the second one
supports a finding.

**2.** UID `1010388`, data at `/data/user/10/com.example.torch`, and no — they cannot read each other.
They are different Unix users with different data directories, and on top of that the two directory
trees are protected by different SELinux category sets *and* encrypted with different CE keys. The
work profile is a genuinely separate sandbox, which is exactly the point of it. On an engagement,
enumerate users with `pm list users` and test each relevant one; forgetting the work profile is a
common omission.

**3.** Real, effective, saved-set and filesystem UID. They differ on processes that deliberately change
identity — a setuid binary starts with real ≠ effective, and a daemon that drops privileges keeps a
saved-set UID it could return to. On an app they are all identical, because Zygote called
`setresuid()` with the same value for all three and the app has no mechanism (and, thanks to seccomp,
no syscall) to change them.

**4.** It is recorded as a **supplementary group**. At install time `PackageManagerService` walks the
app's granted install-time permissions, consults the permission→GID mapping parsed from
`/system/etc/permissions/platform.xml`, and records the resulting GID list — which you can see as field
6 of `packages.list`. When the app is started, Zygote calls `setgroups()` with that list *before*
calling `setresuid()` to drop to the app's UID.

Hooking `java.net.Socket` cannot help because the check is not in Java, or in the framework, or in
`system_server`. It is in the kernel, on the `socket()` syscall path, against the calling process's
group list — enforced historically by the `CONFIG_ANDROID_PARANOID_NETWORK` patch and on modern GKI
kernels by an eBPF program on the `cgroup/inet_create_socket` hook. The group list was fixed at fork
time by a privileged parent and the app has no way to alter it. `socket()` returns `EACCES` before any
DNS lookup or connection attempt occurs.

The actual attack path is not to defeat the check but to route around it: get a *different* app that
holds `INTERNET` to make the request. That is permission re-delegation, and it is why the mitigation is
"audit exported components", not "harden the syscall".

**5.** `CapBnd` is the *bounding set*: a hard upper limit on the capabilities this process — or any
program it ever `execve()`s — may hold. Empty means no capability can ever be acquired, by any route,
for the lifetime of the process and its descendants.

The other two mechanisms are: `/data` and `/storage` are mounted **`nosuid`**, so the setuid bit on a
file there is ignored entirely by the kernel; and `NoNewPrivs: 1` makes the kernel refuse any
privilege-raising `execve()` outright. Any one of the three would be sufficient on its own. All three
are present, which is what properly-executed defence in depth looks like.

**6.** Because the shell has no syscall filter and the app does, the shell can make system calls the
app physically cannot — the kernel will refuse them for the app before they reach any handler. So
"it worked in the shell" establishes nothing about the app's ability to do the same thing. (The same
argument applies independently for the different UID, the different SELinux domain, the different
group list and the different capability sets. There are five separate reasons, not one.)

**7.** The **MCS categories** separate them. Both processes are in the same type, so type enforcement
produces the same answer for both; the MLS/MCS constraint then requires the subject's category set to
*dominate* the object's, and app A's categories do not dominate app B's. If two apps genuinely ended up
with identical category sets they would be mutually readable at the SELinux layer — which is why the
derivation includes per-install randomness on modern releases, and why the DAC layer underneath is
still doing real work. Both checks run; both must pass.

**8.** The data directory is mode `0700` owned by the app's UID. Your shell is UID 2000, so it falls
into the "other" class, which has no bits set at all — no read, and critically no execute, so the
directory cannot even be traversed. The APK is mode `0644` owned by `system`, so "other" has read, and
you get the file.

The consequence is that **the APK is public**. Every string resource, every asset, every value in
`BuildConfig`, and every byte of every bundled `.so` is readable by any app on the device and by anyone
who obtains the APK. A "secret" shipped in an APK has been published. Obfuscation raises the cost of
finding it; it does not change that fact.

**9.** No, it is not faithful. `run-as` gives you the app's **UID and GIDs** and puts you in the app's
data directory, which is exactly what you want for reading files. But it runs in the SELinux domain
`runas_app`, not `untrusted_app`, and it does not install the app's seccomp filter.

So it is excellent for: reading and writing the app's private files, inspecting its databases, pulling
its `shared_prefs`. It is **not** a valid way to test whether the app could make a particular syscall,
reach a particular SELinux-protected resource, or bind a particular service. For those, instrument the
real process (Frida) or use a separate probe APK.

**10.**
- **UID/DAC** — the `Uid:` and `Gid:` lines, plus the `Permission denied` in step 8.
- **SELinux MAC** — the `attr/current` context and the `:c…` categories on both the process and its
  files.
- **seccomp** — `Seccomp: 2`, `Seccomp_filters: 1`.
- **Capabilities** — five all-zero `Cap*` lines, especially `CapBnd`.
- **Network GIDs** — `3003` present or absent in `Groups:`.
- **Isolated / SDK sandboxing** — visible only if such a process is running; look for `u0_i*` names or
  the `isolated_app` / `sdk_sandbox` domains in `ps -A -Z`. Its absence on your device is itself worth
  noting: it means no app you have installed uses it.
- **Package visibility** — *not* visible in `/proc` at all, because it is a framework-level filter in
  `AppsFilter`, not a kernel mechanism. That is the honest answer, and it is a useful reminder that not
  every layer is enforced in the same place. Lab 3 measures this one.

</details>

---

## Success criteria

- [ ] You recorded the device's build type, release and security patch level before starting
- [ ] You obtained the target's UID three independent ways and they agree
- [ ] You can compute `userId` and `appId` from a UID, and back, without looking it up
- [ ] You decoded every entry in the `Groups:` line, and identified 3003 as `AID_INET`
- [ ] You can explain why `INTERNET` cannot be hooked away from inside the app's process
- [ ] You confirmed all five capability sets are zero, and can state what `CapBnd` guarantees
- [ ] You named the three independent mechanisms that block a setuid escalation
- [ ] You confirmed `Seccomp: 2` and `NoNewPrivs: 1`, and observed `0`/`0` in your own shell
- [ ] You parsed a full SELinux context into user, role, type, sensitivity and categories
- [ ] You demonstrated that another app's data directory is unreadable but its APK is readable, and can
      explain both from the mode bits
- [ ] You produced a comparison table covering at least five processes
- [ ] You can state, for each of the seven enforcement layers, where in your evidence it appears — and
      you noticed that one of them does not appear in `/proc` at all
- [ ] You can articulate why a result obtained in `adb shell` does not support a claim about apps
