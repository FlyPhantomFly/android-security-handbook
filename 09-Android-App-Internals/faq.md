# 09 — Android App Internals — FAQ

Real questions, asked in the order people actually ask them. Nothing here is too basic to include; if
you were embarrassed to ask it, it is probably question 1, 2 or 3.

---

## 1. Why does my app have a UID of 10234 and not a username like `sarah` or `com.example.app`?

Because Android's sandbox is enforced by the **Linux kernel**, and the Linux kernel does not know what
a username is. It only knows numbers.

> **Definition — UID (user identifier)**
> A UID is a 32-bit integer the Linux kernel attaches to every process. Every time a process tries to
> open a file, the kernel compares that integer against the file's owner number and permission bits.
> The kernel never sees text.

On a desktop Linux machine, names like `sarah` exist only in `/etc/passwd`, a text file that the
*login program* reads to translate the name you typed into the number the kernel wants. The kernel
still stores `1001`. Android keeps the same design but changes what a "user" means: on a phone there
is one human being, so using UIDs to separate humans would waste the mechanism. Instead Android
repurposes it — **each installed application becomes its own Linux user**. Two apps can then no more
read each other's files than two people can read each other's home directories on a shared server.

The number itself is assigned by `PackageManagerService` at install time from the range 10000–19999
(`Process.FIRST_APPLICATION_UID` to `Process.LAST_APPLICATION_UID`). There *is* a name, and you have
probably seen it — `ps` shows `u0_a234` rather than `10234`. That string is synthesised by Android's
own `getpwuid` implementation in Bionic's `libc` (`bionic/libc/bionic/grp_pwd.cpp`), which decodes the
number arithmetically instead of reading `/etc/passwd`. `u0` means user 0 and `a234` means appId
10000 + 234.

```bash
# adb shell
id -u                                 # the shell's own uid, 2000
pm list packages -U | grep -w package:com.example.app
ps -A -o USER,PID,NAME | grep com.example.app
```

The package name still matters enormously — it is the identity the *framework* uses, and it is what
appears in permission grants, `dumpsys` output and every Binder call. But below the framework, at the
layer that cannot be talked out of a decision, the identity is an integer.

Read [`../21-App-Sandbox/README.md`](../21-App-Sandbox/README.md) for the enforcement side of this.

---

## 2. What is the difference between `/data/data/com.example.app` and `/data/user/0/com.example.app`?

On a modern device there is no difference at all — `/data/user/0` is a **symbolic link** to
`/data/data`. They resolve to the same inode, the same files, the same everything.

```bash
# adb shell
ls -l /data/user
# lrwxrwxrwx 1 root root 10 ... 0 -> /data/data
```

The reason both exist is historical. Before Android 4.2 (API 17) there was exactly one user on a
device, so one directory — `/data/data` — was enough. Multi-user support then needed a per-user path,
so `/data/user/<userId>/<package>` was introduced. To avoid breaking every piece of code and every
hard-coded path in the world, user 0's directory stayed physically at `/data/data`, and
`/data/user/0` became a symlink pointing at it. Users 10, 11 and so on are real directories under
`/data/user/`.

| Path | Real or symlink | User |
|---|---|---|
| `/data/data/com.example.app` | real directory | 0 |
| `/data/user/0/com.example.app` | via symlink `/data/user/0 -> /data/data` | 0 |
| `/data/user/10/com.example.app` | real directory | 10 (work profile etc.) |
| `/data/user_de/0/com.example.app` | real directory | 0, device-encrypted |

> **Pentester's Note**
> Write your tooling against `/data/user/<N>/<pkg>`, never `/data/data/<pkg>`. The moment your target
> is inside a work profile, hard-coded `/data/data` paths silently look at the wrong (personal
> profile) copy of the app and you will report "no sensitive data found" about a directory you never
> examined. `Context.getFilesDir()` returns the `/data/user/N/...` form for exactly this reason.

There is a third path you must not confuse with these: `/data/user_de/0/com.example.app`. That is
*device-encrypted* storage, which is decryptable after boot but before the user enters their PIN.
Question 12 covers it.

---

## 3. Is the package name checkable, or is it spoofable?

Both, and knowing which is which is one of the highest-value distinctions in Android security.

**Inside a single device, the package name is trustworthy.** Only one package with a given name can be
installed for a given user at a time, `PackageManagerService` enforces that, and when your app asks
"who called me?" the answer comes from the kernel-supplied caller UID that Binder stamps on the
transaction — not from anything the caller typed. So the following is sound:

```kotlin
// Server side of a Binder/AIDL or ContentProvider call.
// Binder.getCallingUid() is filled in by the kernel driver. The caller cannot lie about it.
val callerUid = Binder.getCallingUid()
val callerPkgs = packageManager.getPackagesForUid(callerUid)   // may be several if sharedUserId
```

**Outside that device, the package name is just a string in a ZIP file.** Anyone can build an APK
whose manifest says `package="com.yourbank.app"`, sign it with their own key, and install it on a
device that does not already have the real one. Nothing about the name is certified. This is why
"we validate the package name" is never an anti-tamper control on its own.

The thing that *is* unforgeable is the **signing certificate**, because forging it requires the
private key. Every meaningful identity check is therefore package name **plus** signature:

```bash
# host — the only identity check that means anything
apksigner verify --print-certs base.apk
```

```kotlin
// Verify a caller is genuinely the app you think it is (API 28+).
val ok = packageManager.checkSignatures(myPkg, callerPkg) == PackageManager.SIGNATURE_MATCH
// or, for a specific known cert:
val ok2 = packageManager.hasSigningCertificate(
    callerPkg, expectedSha256Cert, PackageManager.CERT_INPUT_SHA256
)
```

> **Warning**
> `getCallingPackage()` on an `Activity` is *not* the same as `Binder.getCallingUid()`. It relies on
> the caller having used `startActivityForResult` and can be absent or misleading. Derive the package
> from the UID, not the other way round.

Related: [`../26-Intent/README.md`](../26-Intent/README.md) and
[`../38-TamperDetection/README.md`](../38-TamperDetection/README.md).

---

## 4. Can two apps share a UID? What exactly does that let them do?

Yes — through the legacy `android:sharedUserId` manifest attribute. Two or more packages that declare
the *same* `sharedUserId` string **and are signed with the same key** are assigned a single appId by
`PackageManagerService`, and every process of every member runs as that one UID.

```xml
<!-- AndroidManifest.xml of BOTH apps -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vault"
    android:sharedUserId="com.example.shared">
```

Once that happens, the sandbox between those packages does not exist. Concretely, the members share:

| Shared thing | Consequence |
|---|---|
| Linux UID | any member can `open()` any other member's private files directly |
| Supplementary GIDs | permission-derived GIDs are the union across members |
| Permission set (effectively) | the runtime permission state is tracked for the shared user |
| Ability to run in one process | `android:process` with a global name lets them share an ART heap |
| `Context.createPackageContext` with code | one member can load another's classes |
| Signature | required to be identical, which is the only thing keeping strangers out |

The reason it is dangerous is **blast radius**. A vulnerability in the least important member — the
little "companion" app nobody audits — is a full compromise of the most important member's private
data. Attackers know this, and the companion app is exactly where they look.

> **Warning**
> `android:sharedUserId` is **deprecated from API 29**. It cannot be added to a new app on modern
> tooling without warnings, and — critically — **it can never be removed from a shipped app**.
> Removing it changes the package's UID, which Android treats as a different identity, so the upgrade
> is rejected and the only path forward for the user is uninstall-and-reinstall, losing all data.

The escape hatch added in API 33 is `android:sharedUserMaxSdkVersion`:

```xml
<manifest
    android:sharedUserId="com.example.shared"
    android:sharedUserMaxSdkVersion="32">
```

This means: "if this app is being installed **fresh** on a device running API 33 or higher, ignore the
shared user and give me my own appId." Existing installs on any device keep the shared UID; only new
installs on new devices get separated. It is a migration mechanism for new users, not a fix for the
installed base.

Lab 3 in [`labs/lab-03-ctf-the-shared-uid-heist.md`](labs/lab-03-ctf-the-shared-uid-heist.md) makes
you exploit this end to end.

---

## 5. How do I tell, from the outside, whether an app uses a shared UID?

Three ways, in increasing order of reliability.

**From the APK, statically** — the manifest attribute is right there:

```bash
# host
aapt2 dump xmltree base.apk --file AndroidManifest.xml | grep -i sharedUser
apktool d base.apk -o out && grep -i sharedUserId out/AndroidManifest.xml
```

**From the running device, via `dumpsys`** — the record shows a `sharedUser=` line instead of a plain
`userId=`:

```bash
# adb shell
dumpsys package com.example.app | grep -E 'userId=|sharedUser'
# sharedUser=SharedUserSetting{a1b2c3 com.example.shared/10234}
```

**From the UID table** — the most reliable check, because it catches shared UIDs regardless of how they
were declared. Two packages with the same UID number *are* sharing, full stop:

```bash
# host
adb shell pm list packages -U | tr -d '\r' | sed 's/package://;s/uid://' \
  | awk '{print $2, $1}' | sort -n \
  | awk '{c[$1]=c[$1]" "$2} END {for (u in c) {n=split(c[u],a," "); if (n>1) print u ":" c[u]}}'
```

The script [`scripts/uid-map.py`](scripts/uid-map.py) does this properly against
`/data/system/packages.list`, including the `<shared-user>` groups, and flags them for you.
you will always find legitimate shared UIDs on any device — `android.uid.system` (1000),
`android.uid.phone` (1001), `android.uid.bluetooth` (1002) and so on. Those are platform components
signed with the platform key. What you are hunting for is a *third-party* group in the 10000+ range.

---

## 6. Why did my Frida attach fail on a non-debuggable app?

Because you are almost certainly trying to use the **non-root** Frida workflow, and that workflow is
built entirely on top of `android:debuggable`.

There are three distinct ways to get Frida into an app, and they fail for different reasons:

| Method | Requires root | Requires `debuggable` | Fails when |
|---|---|---|---|
| `frida-server` running as root on the device | **yes** | no | device is not rooted, or SELinux blocks `ptrace` |
| Frida Gadget embedded in a repackaged APK | no | no | app has signature/integrity checks, or you cannot re-sign |
| Gadget injected via `run-as` / `setprop wrap.<pkg>` | no | **yes** | app is a release build |

The root path uses `ptrace` — the kernel debugging syscall — to stop the target process, map Frida's
agent into it and resume it. `ptrace` across UID boundaries needs privilege, so this path needs root
plus a permissive-enough SELinux stance for the `frida-server` domain. If root is present and it still
fails, look at SELinux denials (`dmesg | grep avc`), at `kernel.yama.ptrace_scope`, and at whether the
app is running in a domain your `frida-server` context is not allowed to `ptrace`.

The non-root paths do not use root, so they need the OS to hand you a legitimate foothold inside the
app's own UID. The only such foothold is `run-as`, and `run-as` explicitly refuses unless the app is
debuggable — the `run-as` binary reads field 3 of `/data/system/packages.list` (the debug flag) and
bails out if it is `0`. Same story for `setprop wrap.<pkg>`, which lets you set `LD_PRELOAD` for a
process Zygote is about to create: on a `user` build that is honoured only for debuggable apps.

So the diagnosis chain is:

```bash
# adb shell
dumpsys package com.example.app | grep -o DEBUGGABLE     # empty output = release build
run-as com.example.app id                                # "not debuggable" = confirmed
getprop ro.build.type                                    # user vs userdebug/eng
getprop ro.debuggable                                    # 1 = whole build is debuggable
id                                                       # are you actually root?
```

```bash
# adb shell (root) — is frida-server really running, and as root?
ps -A -Z | grep frida
```

Your options on a release build without root are: repackage with the Gadget (see
[`../67-BypassingProtections/README.md`](../67-BypassingProtections/README.md)), get a rooted device
or a rooted emulator image, or use a Google APIs (non-Play) emulator image where `adb root` works.

> **Under the Hood**
> Making an APK debuggable by patching `AndroidManifest.xml` and re-signing works, but it changes the
> signature. Any app that pins its own certificate, uses signature-level permissions, or talks to a
> backend that attests the install will notice. Prefer a rooted device for realistic testing.

Full treatment in [`../53-Frida/README.md`](../53-Frida/README.md).

---

## 7. What happens to my app's data when the app is uninstalled?

By default, all of it is destroyed. `PackageManagerService` asks `installd` to run `destroyAppData`
for every user the package was installed for, which removes:

- `/data/user/<N>/<pkg>` — credential-encrypted private data
- `/data/user_de/<N>/<pkg>` — device-encrypted private data
- `/data/media/<N>/Android/data/<pkg>` — app-specific external files (visible as `/sdcard/Android/data/<pkg>`)
- `/data/media/<N>/Android/obb/<pkg>` — expansion files
- `/data/app/.../` — the APK and its splits
- profile data under `/data/misc/profiles/{cur,ref}`

What is **not** removed, and this matters for both privacy reviews and forensics:

| Survives uninstall | Why |
|---|---|
| Files the app wrote to shared media locations (`Downloads`, `Pictures`, `Documents`) | they belong to the media collection, not the app |
| Files written to another app's world-accessible location | different owner |
| Cloud backups (Auto Backup / Google Drive) | server side |
| Data written by a *different* package that shares the UID | that package still exists |
| The record in `packages.xml` if `-k` was used | see below |
| Entries in system logs, usage stats, job scheduler history | system-owned |

Three uninstall variants behave differently:

```bash
# adb shell
pm uninstall com.example.app              # everything above is deleted, all users
pm uninstall -k com.example.app           # DELETE_KEEP_DATA: dirs and record are KEPT
pm uninstall --user 10 com.example.app    # only user 10's data; other users untouched
pm clear com.example.app                  # app stays installed, data dirs emptied and recreated
```

`pm uninstall -k` is the interesting one. The package disappears from the launcher and from
`pm list packages`, but the data directories remain, the appId stays reserved, and
`pm list packages -u` still shows it. Reinstalling the same package name **with a matching
signature** reattaches it to the old data. With a *different* signature the install is rejected until
the leftover record is removed — a classic "why can't I install my rebuilt APK" trap.

> **Pentester's Note**
> On a device you are triaging, `pm list packages -u -3` reveals third-party packages that were
> uninstalled but left data behind. That is often where the interesting artefacts of a removed
> malware sample still live.

AppIds are **reused**. Uninstall an app with appId 10234 and the next install may well
receive 10234. Any file, log entry or database row that recorded only a UID and not a package name is
now ambiguous. Never treat a bare UID from an old artefact as an identity.

---

## 8. Why can a ContentProvider run code before `Application.onCreate()`? Is that a bug?

It is not a bug — it is a documented ordering guarantee, and it is one of the most abused facts in the
Android ecosystem.

When the system needs a new process for your app, `ActivityThread.handleBindApplication()` runs
roughly this sequence:

1. Set up the `LoadedApk`, the `Instrumentation` and the base `Context`.
2. Create the `Application` object, which calls **`Application.attachBaseContext()`**.
3. Call **`installContentProviders()`**, which instantiates every `ContentProvider` declared in the
   merged manifest and calls **`ContentProvider.onCreate()`** on each.
4. Call `Instrumentation.callApplicationOnCreate()`, which calls **`Application.onCreate()`**.

So provider `onCreate()` is guaranteed to run before `Application.onCreate()` and long before any
`Activity` exists. The reason is practical: another process may bind to your provider at any moment,
including as the very thing that caused your process to start, so providers must be live the instant
the process is usable.

Google's own `androidx.startup` library turns this into a feature. A single
`androidx.startup.InitializationProvider` is declared in the library's manifest, and every dependency
that wants early initialisation adds a `<meta-data>` entry pointing at an `Initializer` class. Many
SDKs — analytics, crash reporting, ads, attribution — either use it or ship their own provider that
does the same thing.

> **Warning**
> A provider declared in an AAR's manifest is merged into **your** app's manifest by the Gradle
> manifest merger. You will not see it in your source tree, you did not write it, and it runs before
> your first line of code. From a supply-chain perspective, adding a dependency to `build.gradle` is
> equivalent to granting that dependency arbitrary code execution at process start, inside your UID,
> with your permissions.

For a pentester the takeaway is procedural: never read only the app's `src/main/AndroidManifest.xml`.
Read the **merged** manifest out of the built APK:

```bash
# host
aapt2 dump xmltree base.apk --file AndroidManifest.xml | grep -A 6 'E: provider'
# or, on the device
adb shell dumpsys package com.example.app | sed -n '/Provider Resolver Table/,/Service Resolver Table/p'
```

The demo in [`examples/StartupProviderPersistence/`](examples/StartupProviderPersistence/README.md)
proves the ordering with logcat timestamps, and
[`scripts/trace-app-startup.js`](scripts/trace-app-startup.js) shows it live on any app.

---

## 9. My app has three processes in `ps` but only one UID. Is that a sandbox violation?

No. Processes and UIDs are independent axes. One UID can back many processes, and one process runs as
exactly one UID.

You get extra processes when a component declares `android:process`:

```xml
<service android:name=".WorkerService" android:process=":worker" />
<activity android:name=".HeavyActivity" android:process=":ui" />
```

A value starting with `:` is **private** to the package — the real process name becomes
`com.example.app:worker`, and no other package can join it. A value without the colon is a **global**
process name, and another package may join it only if it has the same UID *and* the same signing
certificate.

What is genuinely surprising the first time you meet it:

| Expectation | Reality |
|---|---|
| One `Application` object per app | **One per process.** Your `Application.onCreate()` runs once in each process. |
| Static fields shared across the app | **Not shared.** Each process has its own class loader, own static state, own ART heap. |
| A singleton is a singleton | It is a singleton *per process*. Three processes, three instances. |
| `getFilesDir()` differs per process | Same directory — same UID, same data dirs. |
| Killing the app kills all of it | `force-stop` does; killing one PID leaves the others alive. |

Because they share a UID, the processes have identical file access and identical permissions. They are
not isolated from each other in any security-relevant way; the split exists for memory management,
crash containment and startup latency, not for security.

The one exception where a separate process *is* a security boundary is
`android:isolatedProcess="true"`, which gives the process a throwaway UID in the 90000–99999 range
with no permissions and no access to the app's data directories. That is how Chrome and WebView
sandbox renderers.

```bash
# adb shell — see it for yourself
ps -A -o USER,PID,PPID,NAME | grep com.example.app
```

The runnable demo is [`examples/MultiProcessDemo/`](examples/MultiProcessDemo/README.md).

---

## 10. What does `android:debuggable="true"` actually enable? Is it "just" the debugger?

It is much more than the debugger. Zygote reads the flag when it specialises the forked process and
changes several things at once, and several userspace tools read it independently.

| Enabled by `FLAG_DEBUGGABLE` | Mechanism |
|---|---|
| `adb shell run-as <pkg>` — a shell **inside the app's UID** | `run-as` checks field 3 of `packages.list`, then `setuid()`s |
| JDWP debugging (`adb jdwp`, Android Studio attach) | Zygote starts the JDWP thread in the new process |
| `am set-debug-app -w <pkg>` (wait-for-debugger) | AMS honours it only for debuggable apps |
| `setprop wrap.<pkg> "LD_PRELOAD=…"` | Zygote wraps the process launch — the classic gadget injection path |
| Java heap dumps / allocation tracking via `am dumpheap` | ART allows it |
| More permissive JIT/AOT and `-Xjdwp` options | ART runtime flags |
| MethodTracing and profiling from any shell | `Debug.startMethodTracing` triggered externally |

`run-as` is the important one. It gives an ordinary `adb shell` (uid 2000) the ability to become uid
10234 for one command, which means read and write access to every private file the app owns:

```bash
# adb shell
run-as com.example.app id
run-as com.example.app ls -la /data/data/com.example.app/shared_prefs
run-as com.example.app cat /data/data/com.example.app/databases/secrets.db > /sdcard/secrets.db
```

That is why shipping a debuggable release build is a finding in its own right, independent of
whatever else the app does: it converts "attacker with USB access" into "attacker with full read/write
on the app's data", with no exploit required. Google Play's pre-launch checks reject debuggable
release APKs for exactly this reason.

What `debuggable` does **not** do: it does not disable SELinux, it does not grant root, it does not
let you `ptrace` other apps, and it is not required for a root-based Frida attach.

---

## 11. Why does `run-as` say "package not debuggable" when I built a debug APK?

Three common causes, in order of frequency.

**The installed APK is not the one you think.** A `release` variant is installed over your `debug`
variant, or the Play Store version is present. Check what is actually on the device rather than what
is in your `build/` folder:

```bash
# adb shell
dumpsys package com.example.app | grep -E 'flags=|versionName|lastUpdateTime'
```

**The `packages.list` record is stale.** `run-as` reads the debug flag from
`/data/system/packages.list`, which is written when the package record changes. If you installed with
an unusual flow, reinstall cleanly (`pm uninstall` then `pm install`) and re-check field 3:

```bash
# adb shell (root)
awk '$1=="com.example.app" {print "uid="$2" debug="$3" datadir="$4}' /data/system/packages.list
```

**You are on a device where `run-as` is restricted.** Some OEM builds and some managed profiles
restrict or remove `run-as`. Also, `run-as` operates on the **current user**; if the app you care
about lives in the work profile, you need the profile's copy, and plain `run-as` targets user 0.

A fourth, subtler cause: the app is installed as an **Instant App** or as an app with
`android:testOnly`, both of which affect what tooling will do with it.

---

## 12. What is the difference between CE and DE storage, and why do I care as an attacker?

**CE** is *credential encrypted* storage: `/data/user/<N>/<pkg>`. Its encryption key is derived from
the user's lock-screen credential (PIN, pattern, password) and is only available after the user has
unlocked the device at least once since boot.

**DE** is *device encrypted* storage: `/data/user_de/<N>/<pkg>`. Its key is bound to the device, not
to any credential, so it is available immediately after boot — before the user has typed anything.

| | CE | DE |
|---|---|---|
| Path | `/data/user/<N>/<pkg>` | `/data/user_de/<N>/<pkg>` |
| Available before first unlock | no | **yes** |
| Context accessor | default `Context` | `createDeviceProtectedStorageContext()` |
| Component opt-in | n/a | `android:directBootAware="true"` |
| Introduced | API 24 (Direct Boot) | API 24 |

Direct Boot exists so that alarm clocks, accessibility services, phone dialers and messaging apps can
function on a device that rebooted at 3 a.m. and has not been unlocked. Those components must be
marked `directBootAware` and must use the DE context for any data they touch before unlock.

> **Pentester's Note**
> DE storage is a recurring source of findings. Developers reach for
> `createDeviceProtectedStorageContext()` to fix a "my `SharedPreferences` are empty at boot" bug and
> quietly move tokens, session identifiers or cached PII into a store that is readable in a
> before-first-unlock forensic acquisition. Always enumerate `/data/user_de/<N>/<pkg>` separately —
> it is not a subdirectory of the CE path and generic recursive scans of `/data/data` miss it
> entirely.

```bash
# adb shell (root)
ls -laZ /data/user/0/com.example.app /data/user_de/0/com.example.app
```

```bash
# host — find code that opts into DE storage
jadx -d out base.apk && grep -rn "createDeviceProtectedStorageContext\|directBootAware" out/
aapt2 dump xmltree base.apk --file AndroidManifest.xml | grep -i directBootAware
```

More in [`../33-Storage/README.md`](../33-Storage/README.md).

---

## 13. What does `adb install` actually do? It cannot just be copying a file.

It is not. Since Android 5.0 the whole installation is driven by a **session**, and `adb install` is a
thin client over the same `PackageInstaller` API that the Play Store uses.

Roughly, in order:

1. `adb` on the host asks the device shell to open a session:
   `cmd package install-create -S <exact byte size>`. The device replies with a session id.
2. `adb` streams the APK bytes into the session: `cmd package install-write -S <size> <sid> base -`,
   with the APK on stdin. Nothing is written to `/data/local/tmp`; the bytes land in a staging
   directory owned by the installer service.
3. `adb` commits: `cmd package install-commit <sid>`.
4. `PackageInstallerSession` hands the staged files to `PackageManagerService`.
5. PMS parses `AndroidManifest.xml`, collects and **verifies the signature** (v1 JAR, v2, v3, v3.1,
   v4 as applicable), and on an upgrade checks that the new signature matches the recorded one.
6. PMS allocates the appId if this is a fresh install, or reuses the existing one, and computes the
   supplementary GIDs from the granted install-time permissions.
7. PMS calls `installd` over Binder to create `/data/user/<N>/<pkg>` and `/data/user_de/<N>/<pkg>`
   with the right owner, mode and **SELinux label** (`u:object_r:app_data_file:s0:c…,c…`).
8. `installd` runs `dexopt`/`dex2oat` to produce the AOT artefacts, unless the compiler filter says
   otherwise.
9. PMS writes `packages.xml` and `packages.list`, then broadcasts `ACTION_PACKAGE_ADDED`.

You can perform every step by hand, which is what
[`labs/lab-02-tracing-the-install-flow.md`](labs/lab-02-tracing-the-install-flow.md) has you do:

```bash
# adb shell
SZ=$(stat -c %s /data/local/tmp/app.apk)
SID=$(pm install-create -r -S $SZ | grep -o '[0-9]\+')
pm install-write -S $SZ $SID base /data/local/tmp/app.apk
pm install-commit $SID
```

Understanding this matters because sessions are where a lot of interesting behaviour lives: staged
sessions for APEX and rollbacks, multi-package atomic installs, the `installerPackageName` attribution
that determines whether an app "came from the Play Store", and the pre-commit verification hooks that
security products use.

---

## 14. Why are there multiple APKs for one app, and does that change the attack surface?

Because of **app bundles**. Instead of shipping one APK containing every language, every screen
density and every CPU architecture, developers upload an Android App Bundle and the store generates a
per-device set: a `base.apk` plus configuration splits.

| Split | Example filename | Contains |
|---|---|---|
| Base | `base.apk` | manifest, DEX, shared resources |
| ABI config | `split_config.arm64_v8a.apk` | native libraries for one architecture |
| Density config | `split_config.xxhdpi.apk` | drawables for one density |
| Language config | `split_config.en.apk` | one language's strings |
| Dynamic feature | `split_payments.apk` | an on-demand feature module, with its own DEX |

```bash
# adb shell
pm path com.example.app
# package:/data/app/~~aB~~/com.example.app-cD==/base.apk
# package:/data/app/~~aB~~/com.example.app-cD==/split_config.arm64_v8a.apk
```

For analysis this changes your workflow in three ways. First, **pull every split**, not just
`base.apk`, or you will be missing native libraries and possibly whole features' worth of DEX:

```bash
# host
for p in $(adb shell pm path com.example.app | tr -d '\r' | sed 's/package://'); do adb pull "$p"; done
```

Second, dynamic feature splits contain **code that only exists after the user triggers a download**.
An app can therefore appear to have no payment/biometric/whatever logic at all in `base.apk`. Tools
that only look at the base APK will report a clean bill of health.

Third, all splits of one app **must be signed with the same key** and share one identity, so there is
no privilege boundary between them. A split is not a sandbox.

See [`../10-APK-Internals/README.md`](../10-APK-Internals/README.md) for the container format itself.

---

## 15. What is `/data/app/~~aB3xK~~/com.example.app-9dK2==/`? Why the tildes and random strings?

Those are randomised path segments, introduced in Android 11 (API 30). Before that, install paths were
predictable — first `/data/app/com.example.app-1/`, later `/data/app/com.example.app-<base64>/`.
Predictable paths made it easier for one app to reason about, race against, or hard-code another app's
code location, and they leaked install/upgrade counts.

The modern layout is:

```text
/data/app/~~<random-32-bit-base64>~~/<package>-<random-32-bit-base64>/base.apk
```

The `~~` markers exist so that the parser can unambiguously separate the random parent directory from
the package-named child. Both random components change on every install and every upgrade.

The practical consequences:

- **Never hard-code the path.** Always resolve it with `pm path <pkg>` or, in code,
  `applicationInfo.sourceDir` and `applicationInfo.splitSourceDirs`.
- Scripts written for Android 9 that glob `/data/app/com.example.app-*/base.apk` silently find
  nothing on Android 11+.
- The path changes after an app update, so any cached path in your tooling goes stale.

The directory itself is owned by `system:system` and is world-executable-traversable so that any app
can `mmap()` the APKs it is allowed to read — APKs are not secret; they are the same bytes the store
served to everyone.

---

## 16. How do work profiles change everything I just learned?

A work profile is a **separate Android user** (usually userId 10) that shares the same physical device
and the same lock screen as the personal profile but has its own instance of everything.

The same package installed in both profiles is, to the kernel, two different applications:

| | Personal profile | Work profile |
|---|---|---|
| userId | 0 | 10 |
| UID for appId 10234 | 10234 | 1010234 |
| CE data | `/data/user/0/com.example.app` | `/data/user/10/com.example.app` |
| DE data | `/data/user_de/0/com.example.app` | `/data/user_de/10/com.example.app` |
| Shared storage | `/storage/emulated/0` | `/storage/emulated/10` |
| SELinux MLS categories | `…,c512,c768` | `…,c522,c768` |

They cannot read each other's data. Crossing profiles requires `INTERACT_ACROSS_USERS` or
`INTERACT_ACROSS_USERS_FULL` (signature/privileged permissions) or an explicit cross-profile intent
filter installed by the device policy controller.

Every `pm` and `am` command takes `--user`:

```bash
# adb shell
pm list users
pm list packages --user 10 | grep example
pm install-existing --user 10 com.example.app
am start --user 10 -n com.example.app/.MainActivity
pm uninstall --user 10 com.example.app
```

> **Pentester's Note**
> Two mistakes recur in work-profile assessments. The first is analysing the personal-profile copy of
> an app and reporting on data the enterprise does not care about. The second is missing cross-user
> attack surface entirely: components that a badly written DPC or a privileged helper exposes across
> the profile boundary are exactly the bugs that matter in a managed deployment. Always enumerate both
> users and diff them.

---

## 17. Why does my app get killed in the background, and can I stop it?

Android is designed around the assumption that memory is always full. The **low memory killer daemon**
(`lmkd`, a userspace daemon at `system/memory/lmkd/`) watches kernel memory pressure signals and kills
processes before the kernel's own OOM killer has to. It picks victims using `oom_score_adj`, a value
that `system_server` writes to `/proc/<pid>/oom_score_adj` for every app process, updated continuously
as the app's importance changes.

| Situation | `oom_score_adj` | Survival |
|---|---|---|
| App the user is looking at | 0 | essentially never killed |
| Visible but not focused | 100 | rarely |
| Foreground service | 200 | rarely |
| Started background service | 500 | sometimes |
| Launcher | 600 | sometimes |
| Previous app | 700 | often |
| Cached | 900–999 | first to die, routinely |

```bash
# adb shell
cat /proc/$(pidof com.example.app)/oom_score_adj
dumpsys activity oom | head -40
logcat -b all | grep -i lowmemorykiller
```

You cannot "stop" it, and you should not try. What you can do is legitimately raise your importance —
run a foreground service with a visible notification, hold the right foreground service type, or use
`WorkManager`/`JobScheduler` so the system schedules your work instead of you keeping a process alive.
The techniques that fight the system (mutually restarting processes, sticky services, alarm loops,
accessibility-service abuse) are exactly the behaviours Play Protect and malware analysts flag.

On top of `lmkd` there are **policy** restrictions: app standby buckets throttle jobs and alarms for
apps the user rarely opens, Doze suspends network and alarms during long idle periods, and
manufacturer "battery optimisation" layers add their own, often aggressive, rules.

```bash
# adb shell
am get-standby-bucket com.example.app
am set-standby-bucket com.example.app rare
dumpsys deviceidle force-idle
```

---

## 18. Where does the SELinux label on my app's files come from, and why does it have `c512,c768` in it?

The label is applied by `installd` when it creates the directory, using `restorecon`-style logic
driven by two policy inputs: `file_contexts` (which says `/data/data/...` is `app_data_file`) and
`seapp_contexts` (which says which *domain* and which *MLS categories* an app gets, based on its
`seinfo`, `targetSdk`, whether it is privileged, and so on).

A typical app data directory therefore looks like:

```text
u:object_r:app_data_file:s0:c234,c256,c512,c768
```

and the process that owns it looks like:

```text
u:r:untrusted_app:s0:c234,c256,c512,c768
```

The four categories are not random. They are an arithmetic encoding of the appId and the userId,
computed by libselinux's Android backend when `seapp_contexts` specifies `levelFrom=all`:

```text
a       = appId - 10000
c[0]    = a & 0xff
c[1]    = 256 + (a >> 8)
c[2]    = 512 + (userId & 0xff)
c[3]    = 768 + (userId >> 8)
```

So appId 10234 in user 0 gives `c234,c256,c512,c768`; the same app in work profile user 10 gives
`c234,c256,c522,c768`.

Why bother, when the UID already isolates apps? **Defence in depth.** SELinux MLS requires an exact
category-set match for access, so even a process that somehow ends up running with the wrong UID, or a
bug that grants a file descriptor across a boundary, is still stopped by the label mismatch. It is a
second, independent lock on the same door.

```bash
# adb shell
ps -A -Z | grep com.example.app
# adb shell (root)
ls -ldZ /data/data/com.example.app
```

```bash
# host — predict the categories for a UID
u=1010234; a=$((u%100000-10000)); n=$((u/100000))
echo "c$((a&255)),c$((256+(a>>8))),c$((512+(n&255))),c$((768+(n>>8)))"
```

Full treatment in [`../22-SELinux/README.md`](../22-SELinux/README.md).

---

## 19. What is an "isolated process" and how is it different from `android:process`?

`android:process` splits your app into several processes that all run as **your UID**. An isolated
process runs as a **throwaway UID in the 90000–99999 range** with essentially no privileges at all.

```xml
<service
    android:name=".RiskyParserService"
    android:isolatedProcess="true"
    android:exported="false" />
```

| | `android:process=":worker"` | `android:isolatedProcess="true"` |
|---|---|---|
| UID | same as the app | fresh UID 90000–99999 |
| Access to app data dirs | full | **none** |
| Permissions | all the app's | none, not even `INTERNET` |
| SELinux domain | `untrusted_app` | `isolated_app` |
| Can call most Binder services | yes | very few |
| Talks to the app via | anything | only the `Service` binding it was started with |
| Purpose | memory and crash management | **security boundary** |

This is how Chrome and the Android WebView sandbox their renderers: the code that parses hostile input
from the internet runs somewhere that, if fully compromised, gives the attacker a UID with no
permissions, no files and almost no reachable kernel or Binder surface.

If you are auditing an app that parses complex untrusted input — media, archives, documents,
scripting — the absence of an isolated process is a design observation worth making. If you are
auditing one that *has* one, the interesting question becomes what the `Service` interface exposes,
because that binder interface is the only bridge out of the sandbox.

---

## 20. `dumpsys package` prints hundreds of lines. What do I actually read?

Nine lines, in this order.

| Read this | Because |
|---|---|
| `userId=` or `sharedUser=` | identity, and whether the sandbox is shared |
| `flags=[ … ]` | look for `DEBUGGABLE`, `ALLOW_BACKUP`, `HAS_CODE`, `EXTERNAL_STORAGE` |
| `targetSdk=` | drives scoped storage, exported-component defaults, SELinux domain, cleartext policy |
| `codePath=` and `splits=` | where the code is and whether you are missing splits |
| `dataDir=` | where the data is, and which user you are looking at |
| `installerPackageName=` / `installInitiatorPackageName=` | provenance: store, sideload, or another app |
| `firstInstallTime=` / `lastUpdateTime=` | forensic timeline |
| `gids=[ … ]` | the actual capability set the kernel granted |
| `User N: … installed= stopped= enabled= instant=` | per-user state, which is easy to overlook |

```bash
# adb shell — the one-liner that gets all of it
dumpsys package com.example.app | grep -E \
 'userId=|sharedUser|flags=\[|privateFlags=\[|targetSdk|codePath=|splits=|dataDir=|installer|InstallTime|lastUpdateTime|gids=|^\s+User [0-9]+:'
```

Then, and only then, dive into the permission blocks and the component resolver tables.
[`scripts/app-identity-dump.sh`](scripts/app-identity-dump.sh) automates this whole triage.

---

## 21. Can I read another app's private files if I am root? If I am `shell`?

**As root: yes, with caveats.** Root defeats the UID check trivially. It does not automatically defeat
SELinux — on a production `user` build with enforcing policy, even root runs in a domain that policy
constrains, and `su` from a rooting solution like Magisk works partly by giving you a permissive-enough
context. On a `userdebug`/`eng` build or an AOSP emulator image, `adb root` plus `setenforce 0` removes
both obstacles.

```bash
# adb shell (root)
ls -laZ /data/data/com.example.app
getenforce                                # Enforcing / Permissive
```

**As `shell` (uid 2000): no, not directly.** The shell user is deliberately given broad *system*
visibility and almost no *app data* access. What shell can do:

| Shell can | Shell cannot |
|---|---|
| List packages, dump `dumpsys package` | read `/data/data/<pkg>` for any app |
| `run-as <pkg>` for **debuggable** apps | `run-as` a release build |
| Read `/sdcard` subject to storage policy | read another app's `Android/data` on API 30+ |
| Install, uninstall, force-stop, clear | read `/data/system/packages.list` |
| Read `/proc/<pid>` for its own processes | read most of `/proc/<pid>` for app processes (hidepid) |
| Pull APKs from `/data/app` | modify them |

That gap is precisely why the `debuggable` flag is such a big deal, and why the standard
non-root test workflow is: repackage the APK with a debuggable manifest, or get root.

---

## 22. Do I need root to do meaningful Android app pentesting?

No, but you will do a different job without it, and you should know which job you are doing.

| Task | Without root | With root |
|---|---|---|
| Static analysis of the APK, DEX, manifest, native libs | full | full |
| Network interception with a proxy | yes, if you can install a CA and defeat pinning | easier — system CA store, Frida |
| Reading app private data | only debuggable apps, via `run-as` | always |
| Frida hooking | repackage with Gadget, or debuggable app | `frida-server` on anything |
| Inspecting `packages.list` / `packages.xml` | no | yes |
| SELinux context inspection of other apps | partial | full |
| Testing exported components with `am`/Drozer | yes | yes |
| Modifying system behaviour, hooking framework | no | yes (Magisk/LSPosed) |
| Realistic "device is stolen and imaged" scenario | no | yes |

The pragmatic recommendation for learning this chapter is a **rooted AOSP emulator image** (an image
without Google Play, so `adb root` works). It costs nothing, cannot be bricked, and gives you the
`/data/system/packages.list` and `ls -Z` access that every lab in this chapter depends on.

```bash
# host — an emulator you can root
emulator -list-avds
emulator -avd Pixel_6_API_34 -writable-system &
adb root && adb shell whoami        # should print "root"
```

---

## See also

- [`README.md`](README.md) — the full chapter
- [`cheatsheet.md`](cheatsheet.md) — every command on one page
- [`labs/lab-01-app-identity-and-uid.md`](labs/lab-01-app-identity-and-uid.md)
- [`labs/lab-02-tracing-the-install-flow.md`](labs/lab-02-tracing-the-install-flow.md)
- [`labs/lab-03-ctf-the-shared-uid-heist.md`](labs/lab-03-ctf-the-shared-uid-heist.md)
- [`../21-App-Sandbox/README.md`](../21-App-Sandbox/README.md)
- [`../33-Storage/README.md`](../33-Storage/README.md)
- [`../53-Frida/README.md`](../53-Frida/README.md)
