# 02 — Linux Basics · FAQ

The questions people actually ask when they open a terminal for the first time, including the ones
they are too embarrassed to ask in a group chat. Nothing here is too basic to be worth answering
properly, and every answer goes past the beginner's version into the part that matters for security
work.

Companion to [README.md](README.md) · [cheatsheet.md](cheatsheet.md) · [mindmap.md](mindmap.md) ·
[labs/](labs/) · [references/README.md](references/README.md)

---

## Getting started

### I have only ever used Windows. Where do I actually get a Linux shell?

You have five options, and you should pick two: one on your own machine for practising, and one on an
Android target for doing the work. They are listed cheapest-first.

| Option | How to get it | What you get | What it is missing |
|---|---|---|---|
| **WSL 2** (Windows Subsystem for Linux) | Open PowerShell as Administrator, run `wsl --install`, reboot, pick a username and password | A real Ubuntu userspace on a real Linux kernel, with `/proc`, real UIDs, real permissions. Full GNU coreutils | It is a virtual machine sharing your Windows filesystem; devices and some kernel tunables differ from a normal install |
| **A Linux virtual machine** | VirtualBox or VMware plus an Ubuntu, Debian or Kali ISO | The most faithful desktop Linux, including a bootloader, `systemd`, and the ability to break things safely with a snapshot to roll back to | Slower, and needs a few GB of disk |
| **`adb shell` to an Android device or emulator** | Install Android Studio (gives you `adb` and the emulator), enable Developer Options and USB debugging on the phone, run `adb shell` | The real target. Every path in this chapter, exactly as it is on the device you will be testing | Toybox, not GNU. Many flags differ. You are UID 2000 (`shell`), not root |
| **Termux** | Install Termux from F-Droid onto an Android phone (the Play Store build is unmaintained) | A shell *on the phone itself*, no cable needed, with a package manager. Excellent for practising commands on a train | It runs as an ordinary app UID inside its own sandbox, so its `$HOME` and `/data/data/com.termux/` are the only places it can write |
| **A cloud shell or a spare Raspberry Pi** | Any VPS, or a Pi with Raspberry Pi OS | A machine you can leave running and log into with `ssh` | Costs money, or costs a Pi |

> **🧠 Mental Model**
> WSL is where you *learn*. `adb shell` is where you *work*. They are different enough that you will
> be caught out at least once — a flag that exists on your laptop and not on the phone — and being
> caught out is how you learn that "Linux" is a kernel, not a fixed set of commands.

The very first thing to type, on whichever you chose:

```bash
# host / WSL / adb shell — all three
id
pwd
uname -a
```

Expected output on WSL:

```
uid=1000(harsh) gid=1000(harsh) groups=1000(harsh),4(adm),27(sudo),...
/home/harsh
Linux DESKTOP-ABC 5.15.153.1-microsoft-standard-WSL2 #1 SMP ... x86_64 GNU/Linux
```

Expected output from `adb shell` on a phone:

```
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),...
/
Linux localhost 5.10.198-android13-4-... #1 SMP PREEMPT ... aarch64 Toybox
```

Read the differences. Your laptop shell is user 1000 in `/home/you`; the phone shell is user 2000
sitting in `/`, running Toybox on an ARM64 kernel. Both are Linux. Neither is the other.

### What is the difference between a shell, a terminal, a console, and Bash?

They get used interchangeably by people who already know the difference, which makes them almost
impossible to learn from context. They are four separate things.

> **📖 Definition — Terminal (terminal emulator)**
> The *window*. A program that draws characters on the screen, captures your keystrokes, and passes
> them to whatever program is attached to it. Windows Terminal, GNOME Terminal, iTerm2, the Termux UI,
> and the pseudo-terminal `adb shell` allocates are all terminal emulators. It has no idea what a
> command is. It draws.

> **📖 Definition — Shell**
> The *program that reads what you typed and does something about it*. It splits your line into
> words, expands `*` and `$HOME`, sets up redirections and pipes, and then asks the kernel to create a
> process to run the command. It is an ordinary user-space program with no special privileges. You
> can have three running at once, or write your own in an afternoon.

> **📖 Definition — Console**
> Historically the physical terminal wired directly to the machine, used for administration. On Linux
> today it means the text screens you reach with Ctrl+Alt+F1..F6, or the kernel's own output device
> (`/dev/console`). You will almost never care about the distinction; "console" in casual speech
> usually means "terminal".

> **📖 Definition — Bash, Mksh, Zsh, Fish, Dash**
> Specific *implementations* of a shell. Bash is the GNU one and the default on most Linux
> distributions. **Android does not ship Bash.** `/system/bin/sh` on Android is **Mksh**, the MirBSD
> Korn shell, chosen for size. Zsh and Fish are user preferences with nicer completion.

The chain, in one line: **you type into the terminal → the terminal feeds the shell → the shell asks
the kernel for a process → the process writes back through the terminal.**

The reason this matters for security work is that "shell injection" is a statement about the middle
box, not the outer one. When an Android app calls `Runtime.getRuntime().exec("sh -c ping " + host)`,
the string is handed to Mksh, which will happily interpret `;`, `` ` ``, `$( )`, `|`, `&&` and `>` in
whatever the user typed into the host field. The terminal is nowhere in that story. Check which shell
you are actually in before assuming a feature exists:

```bash
# host / WSL / adb shell
echo $0
ls -l /system/bin/sh        # on Android: a symlink, and its target is the answer
```

On a phone that last command prints something like:

```
lrwxrwxrwx 1 root shell 4 2009-01-01 00:00 /system/bin/sh -> mksh
```

### Why is there no `C:` drive?

Because UNIX made a different, and frankly better, decision in 1969. Windows gives each storage
device its own namespace root — `C:\`, `D:\`, `E:\` — so a path tells you which physical device it is
on. UNIX has exactly **one** tree, starting at `/`, and storage devices are *attached into* that tree
at a directory of your choosing. That attaching is called **mounting**, and the directory is called a
**mount point**.

> **📖 Definition — Mount**
> To make the contents of a filesystem (on a disk partition, a network share, a loopback image, or
> generated by the kernel) appear at a chosen directory in the single global tree. After
> `mount /dev/block/sda3 /data`, everything under `/data` is served by that device. The directory's
> previous contents are hidden, not deleted, until it is unmounted.

The consequence is that a path like `/data/data/com.example.app/databases/secrets.db` says nothing at
all about which physical partition holds it. To find out, you ask the kernel:

```bash
# host / WSL / adb shell — what is mounted where
cat /proc/mounts
# or, more readable, if the tool exists:
df -h
```

A typical Android line looks like this:

```
/dev/block/dm-6 /data f2fs rw,seclabel,nosuid,nodev,noatime,... 0 0
```

Read it left to right: the device `/dev/block/dm-6` is mounted at `/data`, holding an `f2fs`
filesystem, mounted read-write, with `nosuid` (setuid bits on files here are ignored — a deliberate
hardening choice) and `nodev`.

This single-tree design is exactly what makes the Magisk-style "systemless root" trick possible.
Because a directory's contents are just whatever is mounted there, a privileged process can mount
something *else* over `/system/bin`, and every program that later opens a path under it sees the new
contents. Nothing on the real partition changed, so `dm-verity` is still happy. Section 3.22 of the
[README](README.md#322-mount-namespaces-and-bind-mounts) and
[Lab 03](labs/lab-03-ipc-sockets-and-namespaces.md) take this apart.

### Why do file names have no extensions? How does Linux know what a file is?

Because on UNIX the extension is a *hint to humans*, never a fact the kernel uses. Windows Explorer
looks at `.exe` and `.docx` to decide what to do; the Linux kernel looks at the file's contents and
its permission bits.

There are three separate mechanisms, and confusing them is a classic beginner trap:

| Question | What answers it | How you check |
|---|---|---|
| "Is this file allowed to run?" | The execute permission bit, `x` | `ls -l` — look for `x` in the mode |
| "What kind of data is inside?" | The first few bytes, called a **magic number** | `file thing`, or `xxd thing \| head -1` |
| "How should the kernel run it?" | The first two bytes: `\x7fELF` means a native binary; `#!` means a script and the rest of the line names the interpreter | `head -c 16 thing \| xxd` |

```bash
# host / WSL
file /bin/ls
head -c 4 /bin/ls | xxd
```

```
/bin/ls: ELF 64-bit LSB pie executable, x86-64, ...
00000000: 7f45 4c46                                .ELF
```

Those four bytes `7f 45 4c 46` are the ELF magic — `0x7f` followed by the ASCII letters `E`, `L`, `F`.
Rename `/bin/ls` to `ls.txt` and it still runs, because nothing consulted the name.

> **🔍 Pentester's Note**
> This cuts both ways in Android work. A file called `config.png` inside an APK's assets may be a
> DEX file, an encrypted payload, or a second APK, and a scanner that filters by extension will miss
> it entirely. Always identify by magic bytes. `dex\n035` (hex `64 65 78 0a 30 33 35`) is a DEX file;
> `PK` followed by `\x03\x04` is a ZIP, and therefore possibly an APK or a JAR.

```bash
# host — identify everything in a directory regardless of what it claims to be
find extracted/ -type f -exec file {} +
```

---

## Permissions and identity

### Why does everything say "permission denied"?

Because permission denied is not one error, it is at least five different errors that all print the
same three words. Diagnosing which one you have is a real skill and it starts here. Work down this
list in order.

**1. You are not who you think you are.** Run `id` first, always.

```bash
# adb shell
id
```

```
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),3009(readproc),...
```

You are UID 2000 (`shell`), not root, and not the app. If you were expecting to read
`/data/data/com.example.app/`, you cannot: that directory is owned by the app's own UID and is mode
`0700`.

**2. You lack `x` on a directory somewhere along the path.** To open `/a/b/c/file`, the kernel needs
execute permission on `/`, `/a`, `/a/b` and `/a/b/c`. Execute on a directory means *traverse*, and it
is checked on every single component. A single missing `x` anywhere in the chain denies the whole
path, and the error names the file rather than the directory that actually blocked you.

```bash
# adb shell — walk the path and see which component stops you
ls -ld / /data /data/data /data/data/com.example.app
```

```
drwxr-xr-x  29 root   root    4096 ... /
drwxrwx--x  49 system system  4096 ... /data
drwxrwx--x 180 system system 12288 ... /data/data
drwx------   6 u0_a231 u0_a231 4096 ... /data/data/com.example.app
```

Notice `/data` is `drwxrwx--x`: "other" has `x` but not `r`. That is deliberate and it is the reason
you can `cd /data/data/com.example.app` if you already know the name, but `ls /data/data` returns
nothing useful. It is a deliberate anti-enumeration measure.

**3. SELinux denied it, not the file mode.** Android runs SELinux in enforcing mode. It is a second,
completely independent permission system that is checked *after* the classic bits pass. A denial
looks identical from the shell.

```bash
# adb shell (root) — the only way to tell the two apart
dmesg | grep -i avc | tail -20
# or on newer devices
logcat -b events | grep -i avc
```

If you see a line containing `avc: denied { read } for ... scontext=u:r:shell:s0
tcontext=u:object_r:app_data_file:s0`, the file mode was never the problem. Chapter 22 — SELinux
covers the policy language.

**4. The filesystem is mounted read-only, or `noexec`, or `nosuid`.** `/system` is read-only on a
locked device no matter what the file mode says, and `/sdcard` is mounted `noexec` so a binary there
cannot be run even at mode `0777`.

```bash
# adb shell
grep -E ' /system | /data | /sdcard ' /proc/mounts
```

**5. A seccomp filter blocked the syscall itself.** Rare, but it produces `EPERM` from calls you did
not expect to fail. `grep Seccomp /proc/self/status` shows `2` when a filter is installed.

> **⚠️ Warning**
> "Permission denied" during Android testing is *diagnostic information*, not an obstacle. Each of
> the five causes above has a different fix, and reaching for `su` immediately teaches you nothing
> and hides which layer actually stopped you. Identify the layer first.

### What does `root` mean, and is it the same thing as the `/root` folder, or `/`?

Three different things share the word, which is genuinely confusing, and nobody tells you.

| The word | What it means | How you refer to it |
|---|---|---|
| **root**, the user | UID 0. The superuser. Most permission checks are skipped for it entirely | `id` prints `uid=0(root)` |
| **`/root`**, the directory | Just the home directory of the root user, the same way `/home/harsh` is yours. There is nothing magic about it | `ls -ld /root` |
| **`/`**, the root directory | The top of the single filesystem tree. Everything else hangs off it | `cd /` |

They are unrelated. You can delete `/root` and root the user still exists. On Android `/root` usually
does not exist at all, because there is no interactive root login.

The precise meaning of "being root" is worth stating carefully, because the folklore version ("root
can do anything") is not quite true on modern Android:

> **📖 Definition — UID 0 / root**
> A process whose effective UID is 0. The kernel's discretionary access control checks (the `rwx`
> bits) are bypassed for it. Historically this meant unlimited power. On modern Linux the power of
> UID 0 is split into around forty **capabilities** (`CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_SETUID`
> and so on) that can be dropped independently, and on Android a root process is *still* subject to
> SELinux, which can and does deny operations to UID 0.

That last sentence is the important one for Android. A rooted device's `su` gives you UID 0, but if
the SELinux domain you land in is restricted, you can still be denied. This is why Magisk's `su`
carefully transitions the shell into a permissive-enough domain, and why `getenforce` is one of the
first things to run on a test device.

```bash
# adb shell — three checks, in order
id                    # who am I
getenforce            # Enforcing or Permissive
su -c id              # can I become root at all, and what context do I land in
```

Expected on a rooted device:

```
uid=2000(shell) gid=2000(shell) ...
Enforcing
uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0
```

### How do I turn `drwxr-xr-x` into a number, and back again?

Slowly and mechanically the first ten times, then instantly forever. The string is ten characters:
one type character followed by three groups of three.

```
d rwx r-x r-x
│ │   │   └── other  (everyone else)
│ │   └────── group  (members of the file's group)
│ └────────── owner  (the file's owning user)
└──────────── type   (- file, d directory, l symlink, c/b device, s socket, p FIFO)
```

Within each group of three, the positions are always read, write, execute, in that order, and a `-`
means the bit is off. Each group is one octal digit, built by adding:

| Letter | Value | On a **file** it means | On a **directory** it means |
|---|---|---|---|
| `r` | 4 | Read the contents | List the names inside |
| `w` | 2 | Modify the contents | Create, delete or rename entries inside |
| `x` | 1 | Execute it as a program | **Traverse** it — use it as part of a path |

So `rwx` = 4+2+1 = 7, `r-x` = 4+0+1 = 5, `r--` = 4, `rw-` = 6, `---` = 0.

`drwxr-xr-x` is therefore **755**, and the leading `d` is the type, which is not part of the number.

Going the other way, split the number into digits and expand each:

```
0644  →  owner 6 = rw-,  group 4 = r--,  other 4 = r--   →  -rw-r--r--
0700  →  owner 7 = rwx,  group 0 = ---,  other 0 = ---   →  -rwx------
1777  →  sticky + rwx rwx rwx                            →  drwxrwxrwt
4755  →  setuid + rwx r-x r-x                            →  -rwsr-xr-x
```

The fourth digit, when present, is the special-bit digit: **4 = setuid, 2 = setgid, 1 = sticky**. It
is displayed by replacing the corresponding `x` with a letter — `s` in the owner slot for setuid, `s`
in the group slot for setgid, `t` in the other slot for sticky. If the underlying `x` was off, you
get a capital `S` or `T` instead, which almost always means somebody made a mistake.

Verify your arithmetic against the machine rather than trusting yourself:

```bash
# host / WSL — stat prints the octal mode directly
stat -c '%a %A %n' /etc/passwd /tmp /usr/bin/passwd
```

```
644 -rw-r--r-- /etc/passwd
1777 drwxrwxrwt /tmp
4755 -rwsr-xr-x /usr/bin/passwd
```

[Lab 01](labs/lab-01-filesystem-and-permissions.md) drills this until it is automatic, and
[`examples/permission-arithmetic-drill.md`](examples/permission-arithmetic-drill.md) has thirty
worked problems with answers.

### Why can I `cd` into a directory I cannot `ls`, and list one I cannot enter?

Because `r` and `x` on a directory mean genuinely different things, and this is the single most
useful permission fact in Android work.

- `r` on a directory lets you **read the list of names** it contains. That is all — it does not let
  you look at any of them.
- `x` on a directory lets you **use it as a path component**, that is, resolve a name you already
  know through it. That is all — it does not let you discover names.

So the four combinations behave like this:

| Mode of the directory | `ls dir` | `cat dir/known_file` | Real-world example |
|---|---|---|---|
| `r-x` (5) | Works | Works | A normal readable directory |
| `--x` (1) | **Permission denied** | Works | `/data` and `/data/data` on Android |
| `r--` (4) | Lists names, but every `stat` fails so `ls -l` shows `?` | **Permission denied** | Rare, and almost always a mistake |
| `---` (0) | Denied | Denied | A properly locked directory |

The `--x` row is the interesting one. Android sets `/data/data` to `drwxrwx--x` on purpose: any
process can traverse into a package directory whose exact name it already knows, but no process can
enumerate the list of installed packages by listing the directory. Enumeration is a real information
leak — knowing that a banking app, a dating app and a VPN are installed is worth something to an
attacker — so Android removes the `r` and keeps the `x`.

```bash
# adb shell — demonstrate it yourself
ls /data/data          # denied, or empty
ls -d /data/data/com.android.settings   # succeeds, because you named it
```

> **🧠 Mental Model**
> `r` on a directory is the index at the front of the book. `x` is permission to turn to a page whose
> number you already have. Android tore out the index and left the pages.

### Should I just `chmod 777` it?

No, and it is worth understanding exactly why, because you will see it in real app code and you will
need to write it up as a finding.

`chmod 777` sets read, write and execute for owner, group *and everyone else*. On a multi-user
machine that means every user can modify the file. On Android, where "every other user" means "every
other installed app", it means any app on the device can read and rewrite it. If the file is a
config, another app can change your app's behaviour. If it is a database, another app can read the
session tokens. If it is executable and your app later runs it, another app has just gained code
execution inside your app's sandbox and therefore inside your app's UID.

The specific Android history matters. `Context.MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` were
deprecated in API 17 and, from API 24 (Android 7.0), passing them throws `SecurityException` on
sight. That is how seriously the platform took it. Yet `new File(path).setReadable(true, false)` and
a native `chmod(path, 0777)` still work, so the pattern survives in code that shells out to a bundled
binary and "fixes" a permission error with the largest hammer available.

What to do instead, in order of preference:

1. Work out which of the five causes above actually produced your error. It is usually not the file
   mode.
2. Fix ownership (`chown`) or group membership rather than widening the mode.
3. If you genuinely need to share, share through an interface that can check the caller — a
   permission-guarded `ContentProvider` or a bound service. See
   [24 — IPC](../24-IPC/README.md) and [27 — Content Providers](../27-ContentProviders/README.md).
4. If you must widen the mode, widen the smallest amount: `0640` before `0644`, and never `0666` or
   `0777`.

```bash
# adb shell — how to find this bug on a device you are testing
find /data/data/com.example.app -perm -o+w 2>/dev/null     # world-writable
find /data/data/com.example.app -perm -o+r 2>/dev/null     # world-readable
```

Any hit is a finding. Report it with the mode, the owner, and a demonstration that a *different* UID
can read it — not from a root shell, because root reads everything and proves nothing.

### `adb shell` says I am `shell`, not root. What can I actually do?

Quite a lot, and learning the boundary precisely is more valuable than rooting the device
immediately.

You are UID 2000, the `shell` user, with a set of supplementary groups and the SELinux domain
`shell`. Both layers constrain you.

| You **can** | You **cannot** |
|---|---|
| List every process (`ps -A`) and read a lot of `/proc` | Read another app's `/proc/<pid>/maps`, `fd`, `environ` or `mem` |
| Read logs (`logcat`) | Read another app's private data under `/data/data/` |
| Write to `/data/local/tmp` and execute binaries there | Write to `/system`, `/vendor` or `/product` |
| Install, uninstall and inspect packages (`pm`) | `ptrace` another app's process |
| Grant and revoke runtime permissions (`pm grant`) | Escape the `shell` SELinux domain |
| Take bug reports, screenshots, and `dumpsys` output | Read `/data/misc/keystore` |
| Use `run-as <pkg>` on a **debuggable** app, becoming that app's UID | Use `run-as` on a release build |
| Read `/proc/net/tcp` and see every socket's owning UID | See another app's environment |

The two commands that unlock most beginner workflows without root:

```bash
# adb shell — become the app's UID, but only if the app is debuggable
run-as com.example.app id
run-as com.example.app ls -la /data/data/com.example.app

# adb shell — your writable scratch space, mode 1777, sticky
cd /data/local/tmp && touch probe && ls -l probe && rm probe
```

Expected:

```
uid=10231(u0_a231) gid=10231(u0_a231) groups=... context=u:r:untrusted_app:s0:c231,c256,c512,c768
```

If `run-as` prints `run-as: Package 'com.example.app' is not debuggable`, that is the platform
working correctly. Your options are then an emulator image without Google Play (where `adb root`
works), a rooted device, or repackaging the app with the debuggable flag — see
[10 — APK Internals](../10-APK-Internals/README.md) and [40 — Obfuscation](../40-Obfuscation/README.md)
for what that costs you.

---

## Processes, `/proc` and signals

### What actually is a file descriptor?

A small non-negative integer. That is the whole thing, and the reason it feels mysterious is that
people describe what it *does* rather than what it *is*.

The kernel keeps, for each process, an array of open things. A file descriptor is an index into that
array. When you call `open("/etc/passwd", O_RDONLY)` the kernel finds the lowest free slot, puts a
pointer to its internal open-file object there, and returns the slot number. That number is
meaningless to any other process, exactly as index 3 in your shopping list means nothing in mine.

> **📖 Definition — File descriptor**
> A per-process integer index into the kernel's table of open resources. By convention 0 is standard
> input, 1 is standard output, and 2 is standard error. Anything the kernel can hand you a handle to
> appears here: regular files, directories, pipes, FIFOs, sockets, `eventfd` and `epoll` objects,
> `memfd` regions, and the `/dev/binder` device. This is what the phrase "everything is a file"
> actually means — not that everything is stored on disk, but that everything is *reached through a
> descriptor*.

You can look at the table directly, which is the fastest way to make it concrete:

```bash
# host / WSL
ls -l /proc/self/fd
```

```
lrwx------ 1 harsh harsh 64 Aug  5 12:00 0 -> /dev/pts/1
lrwx------ 1 harsh harsh 64 Aug  5 12:00 1 -> /dev/pts/1
lrwx------ 1 harsh harsh 64 Aug  5 12:00 2 -> /dev/pts/1
lr-x------ 1 harsh harsh 64 Aug  5 12:00 3 -> /proc/1234/fd
```

Descriptors 0, 1 and 2 all point at the terminal, which is why typed input reaches the program and
its output reaches your screen. Descriptor 3 is the directory `ls` opened to do its job.

Two properties make descriptors security-relevant, and both come up constantly on Android:

1. **A descriptor carries its access rights with it.** The kernel checks permissions at `open()` time
   and never again. Once the descriptor exists, holding it *is* the permission — even if the file is
   later deleted, or its mode is tightened, or the process drops privileges.
2. **Descriptors can be inherited and sent.** A child from `fork()` inherits the whole table unless
   the descriptor was opened with `O_CLOEXEC`. And on Android a descriptor can be passed to a
   *completely unrelated* process over Binder as a `ParcelFileDescriptor`, or over a UNIX socket with
   `SCM_RIGHTS`.

Put those together and you get the leaked-descriptor bug class: a privileged process opens something
sensitive, then hands a descriptor to a less privileged process, which can now read a file its own
UID and SELinux context would never have let it open. Checking `ls -l /proc/<pid>/fd` on an app
process is cheap and occasionally spectacular. [Lab 02](labs/lab-02-processes-proc-and-signals.md)
walks it; [Lab 03](labs/lab-03-ipc-sockets-and-namespaces.md) does the passing.

### What is `/proc`, and why does `ls -l` say every file in it is zero bytes?

`/proc` is not on disk. It is a **pseudo-filesystem**: a filesystem whose contents are manufactured by
the kernel at the moment you read them. There is no storage behind it. `cat /proc/uptime` does not
read a file, it calls a kernel function that formats the uptime into your buffer.

That is exactly why the sizes are zero:

```bash
# host / WSL
ls -l /proc/self/status
```

```
-r--r--r-- 1 harsh harsh 0 Aug  5 12:00 /proc/self/status
```

The size field of an inode is a number the filesystem stores. `procfs` has nothing to store, and it
cannot know how long the output will be until it generates it, so it reports 0. Read the file anyway
and you get a thousand bytes. Programs that trust `stat()` before reading — including some naive
scripts and some anti-debug checks — get this wrong, and that is occasionally exploitable.

Three consequences that matter:

1. **You cannot patch `/proc` on disk.** An app checking `TracerPid` in `/proc/self/status` is
   reading a value the kernel computes right then. There is no file to modify ahead of time. This is
   why bypasses hook the `open`/`read` path in libc rather than editing anything.
2. **The contents are per-reader.** `/proc/self` is a magic symlink that resolves to the PID of
   whichever process reads it. `/proc/<pid>/mounts` renders the mount table *of that process's mount
   namespace*, which is the mechanism behind namespace-based root hiding.
3. **Visibility is restricted.** Since Android 9, an app can generally only see its own processes in
   `/proc`, and files like `maps`, `fd`, `environ` and `mem` require the owning UID or root even
   when the directory itself is visible.

```bash
# host / WSL — prove that /proc is generated on demand
cat /proc/uptime; sleep 2; cat /proc/uptime
```

```
1234.56 9876.54
1236.58 9880.61
```

The same "file" produced different bytes two seconds apart, and nothing wrote to it.

### What is a signal, and why does the chapter keep telling me to `kill -3` something I do not want to kill?

A signal is the kernel's way of interrupting a process to tell it something happened. The command
that sends one is called `kill` for the historical reason that terminating a process was the first
use anybody had for it, and the name stuck even though most signals do not terminate anything. `kill`
means "send signal", full stop.

> **📖 Definition — Signal**
> An asynchronous notification delivered to a process, identified by a small number. Each signal has
> a default action (terminate, terminate and dump core, stop, continue, or ignore), and a process may
> install a *handler* function for most of them. When a signal is delivered, the kernel interrupts
> whatever the process was doing and runs the handler.

The ones you need on day one:

| Number | Name | Default action | Why you care |
|---|---|---|---|
| 2 | `SIGINT` | Terminate | What Ctrl+C sends |
| 3 | `SIGQUIT` | Terminate and core dump | **On Android, ART installs a handler that dumps every Java thread stack to logcat.** This is why `kill -3` is a tool, not a weapon |
| 9 | `SIGKILL` | Terminate | **Cannot be caught, blocked or ignored.** The kernel does it, the process never runs again |
| 11 | `SIGSEGV` | Terminate and core dump | Invalid memory access. On Android this produces a tombstone in `/data/tombstones/` |
| 15 | `SIGTERM` | Terminate | The polite one. A process can catch it and clean up. What `kill <pid>` sends by default |
| 17 | `SIGCHLD` | Ignore | Sent to a parent when a child exits |
| 19 | `SIGSTOP` | Stop | Also uncatchable. Freezes the process |
| 5 | `SIGTRAP` | Terminate | The debugger's signal — breakpoints raise it |
| 31 | `SIGSYS` | Terminate | A seccomp filter blocked a syscall |

`kill -3 <pid>` against an Android app is one of the highest-value free actions in mobile testing. It
costs nothing, it does not stop the app, and it produces a complete dump of every Java thread's call
stack — which tells you the class and method names actually in use at that moment, including on an
obfuscated build where a static tool showed you nothing but `a.b.c`.

```bash
# adb shell — get a Java thread dump from a running app
PID=$(pidof com.example.app)
kill -3 $PID

# host — read it
adb logcat -d | grep -A 200 "wait: "
# or find the written trace file:
adb shell ls -l /data/anr/
```

> **⚠️ Warning**
> Signal *numbers* are not fully portable across architectures. `SIGKILL` is 9 and `SIGSEGV` is 11
> everywhere you will meet, but some higher numbers differ between architectures. Use names
> (`kill -QUIT`, `kill -KILL`) in scripts you intend to keep.

### Why does `cat /proc/1/cmdline` run all the words together?

Because the fields are separated by NUL bytes, not spaces, and your terminal draws a NUL as nothing
at all.

The kernel stores a process's command line as the original `argv` array: a sequence of
NUL-terminated strings laid end to end. Writing it out that way is lossless — an argument containing
a space stays one argument — but it looks broken when printed.

```bash
# host / WSL — the confusing version
cat /proc/1/cmdline
```

```
/sbin/init--system
```

Translate the separators into something visible and it makes sense:

```bash
# host / WSL — one argument per line
tr '\0' '\n' < /proc/1/cmdline

# host / WSL — spaces, if you prefer one line
tr '\0' ' ' < /proc/1/cmdline; echo
```

```
/sbin/init
--system
```

The same applies to `/proc/<pid>/environ`, which is a NUL-separated list of `NAME=value` strings.

> **🔍 Pentester's Note**
> Because these files contain bytes below 0x20, `grep` may decide they are binary and print
> `Binary file (standard input) matches` instead of the line you wanted. Use `grep -a` to force text
> mode, or pipe through `tr` first. This bites people constantly when hunting for a token in an app's
> environment: `tr '\0' '\n' < /proc/<pid>/environ | grep -i token`.

---

## Shell mechanics

### The file is right there in `ls`, so why does the shell say "No such file or directory"?

There are four causes, and the error message is the same for all of them.

**1. The file is a script whose interpreter is missing.** The kernel reads the `#!` line, tries to
execute the named interpreter, and it is the *interpreter* that does not exist. The error names your
script, which is thoroughly misleading.

```bash
# host / WSL
head -1 ./deploy.sh
```

```
#!/bin/bash
```

On Android there is no `/bin/bash`, so this fails with "No such file or directory" even though
`deploy.sh` is sitting right there. Fix the shebang to `#!/system/bin/sh`, or run it explicitly as
`sh ./deploy.sh`.

**2. Windows line endings.** A file edited on Windows ends each line with carriage return plus
newline. The kernel then reads the interpreter path as `/bin/sh` followed by an invisible carriage
return, and no such file exists.

```bash
# host / WSL — detect it
file ./deploy.sh              # says "with CRLF line terminators"
head -1 ./deploy.sh | xxd | head -1
# fix it
sed -i 's/\r$//' ./deploy.sh
```

This is the single most common problem for people working from a Windows machine, and the error
message gives you no hint at all.

**3. It is a native binary whose dynamic linker or a needed library is missing.** A 64-bit ELF binary
copied onto a device without the right linker path fails the same way.

```bash
# host — what does this binary need?
readelf -l ./tool | grep interpreter
readelf -d ./tool | grep NEEDED
```

**4. It is a 32-bit binary on a 64-bit-only device.** Recent Android devices ship without 32-bit
support. `file ./tool` will say `ELF 32-bit`, and the loader for it is simply not there.

### What does `2>/dev/null` mean? And `>`, `>>`, `|`, `&`, `&&`?

Every one of these is the shell rearranging file descriptors or process scheduling before the command
runs. Once you see that, they stop being magic punctuation.

| Syntax | What the shell does | Plain English |
|---|---|---|
| `cmd > f` | Opens `f` (truncating), points fd 1 at it | Send normal output to the file, replacing it |
| `cmd >> f` | Opens `f` (appending), points fd 1 at it | Append normal output to the file |
| `cmd 2> f` | Points fd 2 at `f` | Send error messages to the file |
| `cmd > f 2>&1` | Points fd 1 at `f`, then makes fd 2 a copy of fd 1 | Send both to the file. **Order matters** |
| `cmd 2>/dev/null` | Points fd 2 at the kernel's bit bucket | Throw error messages away |
| `cmd < f` | Points fd 0 at `f` | Read input from the file instead of the keyboard |
| `a \| b` | Creates a pipe, points `a`'s fd 1 at the write end and `b`'s fd 0 at the read end | Feed a's output straight into b |
| `cmd &` | Runs it without waiting | Background job |
| `a && b` | Runs `b` only if `a` exited 0 | "and then, if that worked" |
| `a \|\| b` | Runs `b` only if `a` exited non-zero | "or else" |
| `a ; b` | Runs both regardless | "and then, whatever happened" |

`/dev/null` is a character device that discards everything written to it and returns end-of-file when
read. It is not a special shell word; it is a real file you can `ls -l`.

The `2>/dev/null` idiom appears constantly in this chapter for one specific reason: when you run
`find / -perm -4000 -type f` as a non-root user, the kernel denies you a few hundred directories and
`find` prints an error for each, burying the handful of real results. Discarding fd 2 keeps the
signal and drops the noise.

```bash
# adb shell — with and without, to see the point
find /data -perm -4000 -type f
find /data -perm -4000 -type f 2>/dev/null
```

> **⚠️ Warning**
> Discard stderr only once you know what it was going to say. During real testing, an unexpected
> error on fd 2 is often the finding. Run the command bare the first time.

### What is `$PATH`, and why do I have to type `./script.sh` instead of `script.sh`?

`PATH` is an environment variable holding a colon-separated list of directories. When you type a
command with no slash in it, the shell walks that list in order and runs the first matching
executable it finds. If the name contains a slash — including the slash in `./script.sh` — the shell
treats it as a path and does not search at all.

```bash
# host / WSL / adb shell
echo $PATH
```

```
/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin
```

The current directory is deliberately **not** in `PATH` on any sane system. That is a security
decision from the 1970s: if `.` were first in your path, an attacker who could write a file called
`ls` into a directory you were about to visit would get code execution the moment you typed `ls`
there. Requiring the explicit `./` makes the intent unambiguous.

Two things follow that you will use professionally:

**Finding out which binary actually ran.** When a command behaves unexpectedly, the first question is
which one you got.

```bash
# host / WSL
which ls; type ls; command -v ls
# adb shell — `which` exists in toybox
which sh
ls -l $(which sh)
```

**PATH hijacking as an attack.** If a privileged program runs a helper by bare name — `system("id")`
rather than `system("/system/bin/id")` — and an attacker controls `PATH`, the attacker chooses which
`id` runs. This is why Android apps that shell out should always use absolute paths, and why finding
`Runtime.exec("su")` in decompiled code is more interesting than finding
`Runtime.exec("/system/xbin/su")`.

```bash
# adb shell — demonstrate the mechanism harmlessly in your own scratch directory
mkdir -p /data/local/tmp/fakebin
printf '#!/system/bin/sh\necho HIJACKED\n' > /data/local/tmp/fakebin/id
chmod 755 /data/local/tmp/fakebin/id
PATH=/data/local/tmp/fakebin:$PATH id
```

```
HIJACKED
```

Then clean up: `rm -rf /data/local/tmp/fakebin`. Nothing outside your own scratch directory was
touched, and `PATH` was set only for that one command.

---

## Android specifics

### Everyone says "Android is Linux", but half the commands I learned do not work on the device. Why?

Because Android keeps the Linux **kernel** and throws away almost the entire GNU/Linux **userspace**.
"Linux" in everyday speech means both, and the split is exactly where your commands stop working.

| Thing | Desktop Linux | Android | Symptom when you get it wrong |
|---|---|---|---|
| C library | glibc | Bionic, at `/apex/com.android.runtime/lib64/bionic/libc.so` | A binary built for a normal Linux will not run |
| Core utilities | GNU coreutils | **Toybox** — one binary, BSD-flavoured flags | `ls --color=auto` and `grep -P` fail |
| Shell | Bash | **Mksh** | `[[ ]]`, arrays and `$'...'` behave differently or not at all |
| Init | systemd | Android `init` reading `.rc` files | `systemctl` does not exist |
| Package manager | `apt`, `dnf` | `PackageManagerService`, driven by `pm` | `apt install` does not exist and never will |
| Logging | `journald`, `/var/log` | `logd` ring buffers, read with `logcat` | `/var/log` is empty or absent |
| Home directory | `/home/you` | `/data/data/<package>` per app | `~` may not expand to anything useful |
| Users | One per human | **One per application** | `/etc/passwd` is nearly empty; `id` shows `u0_a231` |

The practical fix is to ask the tool what it supports instead of assuming:

```bash
# adb shell — what commands does this device even have?
toybox
# and what flags does one of them take?
toybox ls --help
grep --help 2>&1 | head -20
```

When a flag you need genuinely does not exist, push a static BusyBox build to `/data/local/tmp` and
call it by absolute path. Do **not** install it into `/system`: you would be modifying the
environment you are supposed to be measuring, and on a locked device you cannot anyway.

```bash
# host
adb push busybox /data/local/tmp/
adb shell chmod 755 /data/local/tmp/busybox
# adb shell
/data/local/tmp/busybox find /data -perm -4000 2>/dev/null
```

### Do I need to root my phone to do this chapter?

No. Do the labs in this order of preference and root nothing until you must:

1. **WSL or a Linux VM** for everything that is generic Linux — permissions, `/proc`, signals, FIFOs,
   UNIX sockets, namespaces. That is most of the chapter, and you have full control there.
2. **An Android emulator from Android Studio, using a system image *without* Google Play.** Those
   images allow `adb root`, which gives you a root shell with no modification to any real device.
   This is the correct environment for the Android-specific parts of Labs 01–03.
3. **A physical device with USB debugging**, as UID 2000, plus `run-as` on a debuggable app you built
   yourself. Enough for a great deal of real work.
4. **A rooted physical device**, only when you need to inspect an app you did not build, on real
   hardware, with a real TEE.

> **⚠️ Warning**
> Rooting a device is not reversible on all models, voids warranties, trips Play Integrity, and
> permanently changes the security state you may later want to measure. It also means the device is
> no longer a fair model of a user's phone. Keep a stock device for verifying findings and a rooted
> one for exploring. Never root a device you do not own, and never test against an app or a device
> you are not explicitly authorised to test.

The emulator route is genuinely sufficient for this chapter:

```bash
# host — with an AVD running a non-Play system image
adb root
adb shell id
```

```
restarting adbd as root
uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0
```

If `adb root` answers `adbd cannot run as root in production builds`, you picked a Google Play image.
Create a new AVD and choose a plain "Google APIs" or "AOSP" image instead.

### What is the difference between `/sdcard`, `/storage/emulated/0` and `/data/media/0`?

They are three names for the same bytes, presented through three different layers, and the layer you
go through decides what you are allowed to see.

| Path | What it is |
|---|---|
| `/data/media/0` | The **real** files, on the real `/data` partition, owned by the `media_rw` group. Only reachable with root |
| `/storage/emulated/0` | A **FUSE** view of those files, served by the `MediaProvider` app, which synthesises ownership and applies Scoped Storage rules per calling app |
| `/sdcard` | A **symbolic link** to `/storage/self/primary`, which is itself a per-process bind mount pointing at the right `/storage/emulated/<user>` for whoever is asking |

```bash
# adb shell
ls -ld /sdcard
readlink -f /sdcard
grep -E 'fuse|/storage' /proc/mounts | head
```

```
lrwxrwxrwx 1 root root 21 2024-01-01 00:00 /sdcard -> /storage/self/primary
/storage/emulated/0
/dev/fuse /storage/emulated fuse rw,nosuid,nodev,noexec,noatime,...
```

Three facts fall out of that output, and all three matter:

- `nosuid` and `noexec` mean a setuid bit on `/sdcard` is ignored and a binary there cannot be
  executed. Pushing a tool to `/sdcard` and trying to run it will fail; `/data/local/tmp` is your
  scratch space precisely because it is not mounted `noexec`.
- Because `/storage/self/primary` is a **per-process bind mount**, two different apps looking at the
  "same" path can genuinely see different contents. This is the same namespace mechanism that makes
  systemless root work, applied to storage.
- Anything an app writes to shared storage should be treated as public. The permission gate is
  enforced by `MediaProvider` in userspace, not by classic file bits, and any app with the relevant
  media permission — or the user with a file manager — can read it.

Full treatment of the storage model is in chapter 33 — Storage; the namespace mechanism underneath it
is [Lab 03](labs/lab-03-ipc-sockets-and-namespaces.md).

---

## Where to go next

| If you are unsure about | Go to |
|---|---|
| Bits, hex, endianness, what a process is | [01 — Computer Science Basics](../01-Computer-Science-Basics/README.md) |
| Navigating, `ls -l`, octal modes, Android partitions | [Lab 01](labs/lab-01-filesystem-and-permissions.md) |
| `/proc`, `TracerPid`, signals, `kill -3` | [Lab 02](labs/lab-02-processes-proc-and-signals.md) |
| FIFOs, UNIX sockets, `/proc/net/tcp`, namespaces | [Lab 03](labs/lab-03-ipc-sockets-and-namespaces.md) |
| Putting all of it together under pressure | [Lab 04 — CTF](labs/lab-04-ctf-the-hidden-flag.md) |
| What a program *is*, before reading more code | [03 — Programming Fundamentals](../03-Programming-Fundamentals/README.md) |
| How these primitives become the app sandbox | [21 — App Sandbox](../21-App-Sandbox/README.md) |
| Where Binder replaces classic UNIX IPC | [24 — IPC](../24-IPC/README.md) |
| Every term in this file, defined once | [79 — Glossary](../79-Glossary/README.md) |
