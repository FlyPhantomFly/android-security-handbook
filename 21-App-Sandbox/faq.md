# 21 — App Sandbox · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. What actually *is* the sandbox? Is it a virtual machine?**

No, and this is the single most common misconception. There is no virtualisation, no container
runtime, no hypervisor and no per-app filesystem image. The "sandbox" is ordinary Linux, used
carefully: every installed app is given its **own Unix user account**, its files are owned by that
user with mode `0700`, and the kernel refuses cross-user access exactly as it would on a shared
university server in 1990.

Everything else — SELinux, seccomp, empty capabilities, network GIDs — is defence in depth stacked on
top of that one idea. If you remember one sentence from the chapter, it is *"each app is a separate
Linux user."*

---

**2. Where does the number in `u0_a288` come from?**

`u<userId>_a<appId - 10000>`. So `u0_a288` is Android user 0, app ID `10288`, and the real UID is
`10288`. `u10_a288` is the same package in the work profile, UID `1010288`.

The formula you will use constantly:

```
uid    = userId * 100000 + appId
userId = uid / 100000
appId  = uid % 100000
```

`u0_i9` is an isolated process: UID `99009`.

---

**3. I ran `content query --uri content://com.example.target.provider` from `adb shell` and it
returned rows. Is that a finding?**

**No — not yet.** `adb shell` runs as UID **2000** (`AID_SHELL`) in the SELinux domain `shell`. That
user has no seccomp filter, a different supplementary group list, and platform permissions that no
installed app holds. It can start components, read providers and traverse directories that an
ordinary app cannot.

Proving that the shell can reach something tells you nothing about whether *an app the user installs*
can reach it. That is a different experiment with a genuinely different answer. Repeat it from an
installed probe APK (see [`labs/lab-03-attacker-app.md`](labs/lab-03-attacker-app.md)) before you
write the sentence "any third-party application can…".

Run both, record both. The gap between the two columns is where credibility lives.

---

**4. Can another app read my `SharedPreferences`?**

No — not through the filesystem. Your data directory is mode `0700` and owned by your UID, and
crucially the missing **execute** bit on the directory means another app cannot even traverse into it
to `stat()` a file, regardless of that file's own permissions. SELinux MCS categories then block the
path a second time.

It can, however, read them if: you are running a **debuggable** build (`run-as`), the device is
rooted, the user takes a backup and you left `allowBackup` at its default, you copied the values to
shared storage, you put them on the clipboard, or you hand them out through an exported component.
Every real-world "SharedPreferences leak" I have seen was one of those six, not a sandbox failure.

---

**5. Then why is "secrets in SharedPreferences" reported so often?**

Because the interesting question is not *"can another app read it"* — usually no — but *"what is the
credential, how long does it live, is it bound to anything, and what does it unlock?"*

A long-lived bearer token in plaintext prefs is a real finding, because the adversary who matters is
the **user with the device**, or someone who obtains the device, or the backup channel. Write the
finding in those terms. Writing "another app can read it" when it cannot is how a report gets
dismissed.

---

**6. What is the difference between `android:process` and `android:isolatedProcess`? They look the
same.**

They are one word apart and an entire security boundary apart.

| | `android:process=":worker"` | `android:isolatedProcess="true"` |
|---|---|---|
| Separate process | Yes | Yes |
| Separate **UID** | **No — same app UID** | Yes, 99000–99999 |
| Permissions | All of the app's | **None** |
| Data directory | The app's | None exists |
| Network | Yes | No |
| SELinux domain | `untrusted_app` | `isolated_app` |

`android:process` is a *memory and lifecycle* tool. It gives you a crash boundary and lets you
release memory by killing a process. It gives you **zero** isolation: the new process has the same
UID, so it can open every file the main process can.

Reporting "the parser runs in a separate process, so it is isolated" because you saw
`android:process` is a real and common mistake.

---

**7. Why can any app read another app's APK? Isn't that a leak?**

It is deliberate. `/data/app/…/base.apk` is mode `0644` owned by `system`. `PackageManager` hands out
`ApplicationInfo.sourceDir` for any package you are permitted to see, and the platform relies on this
for a lot of ordinary functionality.

The consequence you must internalise: **anything shipped inside the APK is public.** API keys in
`BuildConfig`, in `strings.xml`, in `assets/`, or in a `.so` are shipped to every user and every app on
every device. Obfuscation changes the cost of finding them, not the fact that they are there.

The randomised `~~<base64>` path segments added in Android 11 are anti-fingerprinting, not access
control.

---

**8. `CapEff` is all zeros on my target. Did something go wrong?**

That is correct and expected. Android app processes hold **no capabilities at all** — `CapInh`,
`CapPrm`, `CapEff`, `CapBnd` and `CapAmb` are all `0000000000000000`.

The one to look at is `CapBnd`, the *bounding* set. An empty bounding set is an upper limit on what
this process, or anything it ever `execve()`s, may hold. Combined with `nosuid` on `/data` and
`NoNewPrivs: 1`, it means there are three independent reasons an app cannot escalate by dropping a
setuid binary somewhere. Any one would be enough. All three are present.

If you ever see non-zero capability sets on something you believed was an ordinary app, stop and work
out what it actually is — it is a system app, a daemon, or your shell.

---

**9. What does `Seccomp: 2` mean, and why is my shell showing `0`?**

`Seccomp:` in `/proc/<pid>/status` is the seccomp mode: `0` = disabled, `1` = strict, `2` =
`SECCOMP_MODE_FILTER`. Every app process forked from Zygote has a BPF filter installed, so it shows
`2`.

Your `adb shell` shows `0` because the shell is **not an app** and no filter was installed on it. That
one-line difference is a compact demonstration of why "I tested it from `adb shell`" is not a valid
experiment for app-reachability questions.

---

**10. Does seccomp block `ptrace`? I keep reading that it does.**

No. An app is permitted to `ptrace` its own processes and threads — that is what makes in-process
crash handlers, some debuggers and a good deal of self-hooking work.

What stops *cross-app* `ptrace` is three other things: DAC (different UID), SELinux (`untrusted_app`
has no rule permitting `ptrace` on another app's domain), and the Yama LSM's `ptrace_scope`. Naming
the wrong mechanism in a finding is the fastest way to have a developer dismiss the whole report.

---

**11. Why is `INTERNET` special? It is just a `normal` permission.**

Because it is the only common permission enforced by the **kernel** rather than by a framework check.
`platform.xml` maps `android.permission.INTERNET` to the group `inet` (**GID 3003**,
`AID_INET`). `PackageManagerService` computes the app's supplementary GID list at install time, and
Zygote calls `setgroups()` with it before dropping to the app's UID.

Socket creation is then gated on that group membership — historically by the out-of-tree
`CONFIG_ANDROID_PARANOID_NETWORK` patch, and on modern GKI kernels by an eBPF program attached to the
`cgroup/inet_create_socket` hook.

Invert your intuition about it. Its **policy** is the weakest possible — granted silently at install
to essentially every app, never shown to the user, not revocable at runtime. Its **mechanism** is the
strongest in the system. Those are independent variables; keep them separate in your head and in your
reports.

---

**12. So can I bypass `INTERNET` with Frida?**

Not from inside the app's own process, no. You can hook `java.net.Socket`, `OkHttp`, `HttpURLConnection`
and anything else you like; the underlying `socket()` syscall still returns `-EACCES`, because the check
is in the kernel against a group list that was fixed at fork time by a privileged parent.

What an attacker actually does is **permission re-delegation**: find another app on the device that
*does* hold `INTERNET` and has an exported component that will send data on request. That is why the
platform's answer to this problem is "audit exported components", not "block the syscall harder".

---

**13. Is root a sandbox escape?**

No. Root is outside the sandbox's threat model. The sandbox is designed to separate mutually
distrusting **apps** on a device whose kernel and system are intact; it makes no promise against the
device owner.

This matters practically: if a finding requires root, say so, price it accordingly, and name the
adversary. "An attacker with root can read the token" is true of every app that has ever existed and
is not a finding on its own. "A malicious app with no permissions can read the token" is a finding.

---

**14. My root shell says `uid=0` but I still get "Permission denied". What?**

SELinux. UID 0 defeats DAC — the kernel's discretionary check short-circuits for `CAP_DAC_OVERRIDE` —
but SELinux has **no root exemption**. A process running as UID 0 in a domain with no `allow` rule for
the target type is refused, full stop.

One command distinguishes the two cases every time:

```bash
# adb shell as root
dmesg | grep -i avc
```

An `avc: denied` line naming your source context is SELinux. No `avc` line plus `EACCES` in `strace`
is DAC. Recognising this instantly costs nothing and is a genuine mark of experience; confusing them
in a report is a credibility hit.

Magisk's `su` deliberately transitions you into a context whose policy has been patched to allow
almost everything, which is why it usually "just works" and why unpatched `setuid` root does not.

---

**15. Why does `run-as` say "package not debuggable"?**

Because it is not. `run-as` is a small setuid/setgid-capable binary that reads
`/data/system/packages.list`, looks at **field 3** of the target package's line, and refuses unless it
is `1` — the `FLAG_DEBUGGABLE` bit from the manifest.

The gate exists because a debuggable app can already be attached to with `jdb` and fully inspected, so
`run-as` grants nothing that was not already available. On a release build it would be a straight
privilege escalation for UID 2000.

Two traps. On a `userdebug` or `eng` build, `ro.debuggable=1` makes `run-as` work on **everything** —
so never generalise a finding from such a device to a production one. And repackaging a release APK to
add `android:debuggable="true"` changes the signature, which breaks signature checks, certificate
pinning tied to the signing key, and integrity attestation; note that in the methodology when you do
it.

---

**16. If the sandbox is so good, where do real findings come from?**

Almost entirely from things the sandbox never claimed to cover:

- Components the developer **exported** — activities, services, receivers, and above all providers.
- Data the app wrote to **shared storage**, where it lives on after uninstall.
- `allowBackup` left at its default, so the data leaves through the backup channel.
- The **clipboard**, screen capture, and the absence of `FLAG_SECURE`.
- `sharedUserId` merging a hardened app with a neglected sibling.
- A third-party **SDK** that has the app's UID, memory, permissions and network.
- Trusting the private data directory for **integrity** — licence flags, trial timers, feature gates —
  against the user, who owns the device.

Write those findings as "the developer relied on the sandbox against an adversary it was not designed
to stop", not as "the sandbox is broken". The second sentence is false and everyone reading the report
knows it.

---

**17. What is `sharedUserId` and why do you keep saying to grep for it?**

`android:sharedUserId="com.vendor.suite"` in two apps signed with the same key makes the platform give
them **the same UID**. They share a data directory tree, the same SELinux domain and the same MCS
categories, and can read each other's files freely.

It is deprecated (API 29) and `android:sharedUserMaxSdkVersion` (API 32) exists so an app can graduate
out of it for new installs. But it is still out there, because removing it changes an installed app's
UID and orphans its data.

Grep for it on every engagement, because when it is present your entire analysis must be done at the
granularity of the **shared UID group**, not the app. The finding shape is: "the hardened banking app
shares a UID with `com.vendor.updater`, whose exported provider is unprotected; compromising the
updater yields the bank's credential store, because they are the same Unix user." That is far stronger
than the exported provider alone.

---

**18. `isolatedProcess` sounds great. Why doesn't everyone use it?**

Because it is genuinely restrictive, and that is the point. An isolated process has no UID of yours, no
permissions, no data directory, no network, and access to a tiny allowlist of Binder services. The only
data it ever sees is what you hand it over its Binder connection or as a passed file descriptor.

That makes it perfect for a **parser** — a video decoder, a PDF renderer, an HTML engine — and useless
for anything that needs to touch your state. The platform uses it exactly that way: WebView renderer
processes and the media extraction/software-codec stack.

When you see it in a target's manifest, write it up as a **positive** finding in a "controls observed"
section. Reports that only ever list problems train clients to read them adversarially, and a genuine
compliment makes the criticisms land harder.

---

**19. An app in the SDK sandbox has UID 20388 and the app is 10388. Coincidence?**

No — `Process.toSdkSandboxUid()` is literally `appUid + 10000`, landing the SDK Runtime process in the
20000–29999 range. So you can read a sandbox UID and immediately know which app it belongs to.

Do not assume a target's ad SDKs are sandboxed, though. The SDK Runtime is opt-in and adoption is
partial. Check for `<uses-sdk-library>` in the manifest and a `com.android.sdksandbox` process at
runtime. In the common case where they are absent, every third-party SDK in the APK runs with the
app's full identity — same process, same memory, same permissions, same network — and that belongs in
the report's third-party risk section.

---

**20. Can an app see what else is installed on the device?**

Not by default since Android 11 (targetSdk 30). Package visibility filtering means an app sees itself,
a small set of always-visible system packages, packages it interacts with through certain APIs, and
whatever it declares in `<queries>`. `QUERY_ALL_PACKAGES` lifts the restriction and is a restricted
permission on Play.

Two things to be careful about. It is a **privacy control, not a security boundary** — it never makes
an exported component unreachable; an attacker simply declares the target. And when *your own probe
app* forgets its `<queries>` block, the symptoms are silent and look exactly like absence:
`NameNotFoundException`, `null` from `resolveActivity()`, `ActivityNotFoundException`,
`IllegalArgumentException: Unknown URL`. Concluding "nothing is reachable" because your own manifest
hid the target is a self-inflicted false negative, and it is common.

---

**21. Why does `/proc` show me almost nothing on a modern device?**

Android 10 hardened `/proc` with `hidepid=2`-equivalent behaviour: an app sees only its own processes.
Before that, `/proc/<pid>/` for other apps exposed a genuinely useful side channel — process names
revealed which apps were installed and running, and `/proc/net/tcp` revealed connection state.

`AID_READPROC` (GID 3009) is the group that lifts this, and no ordinary app has it. If a probe of yours
worked on an old device and returns nothing on a new one, this is usually why.

---

**22. What is the difference between CE and DE storage?**

**CE** — credential encrypted — is `/data/user/<userId>/<pkg>`, and it is only decryptable after the
user has unlocked the device for the first time since boot. That is where essentially all app data
lives.

**DE** — device encrypted — is `/data/user_de/<userId>/<pkg>`, decryptable as soon as the device boots.
It exists for Direct Boot: alarm clocks, accessibility services, and messaging apps that must function
before first unlock.

Security consequence: anything a developer puts in DE storage to make it available before unlock is
available to an attacker with the device *before* they defeat the lock screen. It is a small directory
and worth reading first.

---

**23. Is the clipboard really that bad?**

It is a system-wide shared buffer, which is exactly what a clipboard has to be. Android 10 stopped
background apps reading it, Android 12 shows a toast when an app reads it, and Android 13 auto-clears
sensitive content after a period. But a foreground app can still read whatever the user last copied.

For your report the relevant behaviours are: does the target **put** credentials, tokens, seed phrases
or card numbers on the clipboard (a `setPrimaryClip` grep finds this), and does it mark them with
`ClipDescription.EXTRA_IS_SENSITIVE`? Password managers and crypto wallets are the classic cases.

---

**24. What is a file-descriptor leak and why does it defeat the sandbox?**

Because a file descriptor is **access that has already been granted**. Once a privileged process opens
a file and passes the descriptor across a Binder transaction or a UNIX socket with `SCM_RIGHTS`, the
receiving process can read and write through it — and the kernel never rechecks the receiver's UID
against the file's permissions. The check happened at `open()` time, in the sender.

That is why `ContentProvider.openFile()` implementations that concatenate a caller-supplied path are
so serious: the attacker names a file, the *provider* opens it with the provider's authority, and hands
back a descriptor that works. Path traversal turns into arbitrary file read as the target app. It is
escape class 5 in §3.15 and the subject of
[`labs/lab-04-exported-components.md`](labs/lab-04-exported-components.md).

---

**25. What actually counts as a sandbox escape, then?**

Six classes, and only the first is an escape in the strict sense:

1. **Kernel vulnerability** — a bug in a syscall or driver reachable from `untrusted_app`. The real
   thing; the reason seccomp exists.
2. **Privileged service vulnerability** — memory corruption or logic flaw in `system_server`,
   `installd`, or a vendor HAL.
3. **SELinux policy misconfiguration** — usually a vendor-added `allow` rule that is too broad.
4. **Confused deputy via a system app** — a privileged component that performs an action on your
   behalf without checking who asked.
5. **File-descriptor leak across the boundary** — question 24.
6. **Binder transaction handling bug** — parsing an untrusted parcel in a privileged process.

Everything else you will find on an app engagement is a misconfiguration *within* the sandbox, not an
escape from it. Say which one you have; the distinction is the difference between a platform bug and
an app bug, and they go to different people.

---

**26. Why does the chapter keep insisting the runtime is not a boundary?**

Because inside a single process there is no boundary at all. `private` is a compiler and verifier
convention. Reflection walks straight through it. Native code in the same process shares the address
space with the managed heap. A hooking framework rewrites method entry points at will.

The real boundary is drawn by the kernel — UID, page tables, seccomp, SELinux — and it is drawn
*between processes*, never inside one. Any control an app implements against an attacker who is
already executing in the app's own process is a speed bump, and should be described that way.

The correct place for a decision you must not let the user change is a server you control.
