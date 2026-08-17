# 02 — Linux Basics · References

Every entry says **why you would open it**, not merely what it is. A link with no reason to click it
is noise, and this chapter has enough surface area already.

Two conventions used throughout, both inherited from
[chapter 01](../../01-Computer-Science-Basics/references/README.md):

- Where a deep link would be guessed rather than known, the project or documentation root is linked
  and the specific page is described in words.
- AOSP entries give **directory and file paths only**, never line numbers. Paths are stable across
  releases; line numbers are not.

Back to [README.md](../README.md) · [cheatsheet.md](../cheatsheet.md) · [faq.md](../faq.md) ·
[mindmap.md](../mindmap.md) · [labs/](../labs/)

---

## 1. Manual pages — and how to actually read one

The manual is installed on every Linux machine and is the single most under-used resource by
beginners, almost entirely because nobody explains its structure. Ten minutes here saves you months.

### The section numbers

`man` is divided into numbered sections, and the same name can appear in several of them. When you
see `open(2)` or `proc(5)` written in documentation, that number is telling you which section to look
in. Getting this wrong is why `man open` shows you the wrong page.

| Section | Contains | Ask for it with | Example you will need |
|---|---|---|---|
| **1** | User commands — the things you type | `man 1 ls` | `ls(1)`, `chmod(1)`, `find(1)`, `kill(1)` |
| **2** | System calls — the kernel interface | `man 2 open` | `open(2)`, `execve(2)`, `ptrace(2)`, `mount(2)` |
| **3** | Library functions — C library, not the kernel | `man 3 printf` | `printf(3)`, `malloc(3)`, `fopen(3)` |
| **4** | Device and special files | `man 4 null` | `null(4)`, `random(4)` |
| **5** | File formats and configuration files | `man 5 proc` | `proc(5)`, `passwd(5)`, `fstab(5)` |
| **7** | Overviews, conventions and miscellany | `man 7 credentials` | `credentials(7)`, `capabilities(7)`, `namespaces(7)`, `signal(7)` |
| **8** | System administration commands | `man 8 mount` | `mount(8)`, `ld.so(8)` |

Note the recurring trap: `chmod(1)` is the command you type, `chmod(2)` is the system call it makes,
and `printf(1)` and `printf(3)` are different things with different escape handling. Sections 2 and 7
are where the security content lives.

### The structure of a page

Every page has the same headings in the same order. Read them in this order rather than top to
bottom:

1. **SYNOPSIS** first — it tells you the exact argument shape in three lines.
2. **DESCRIPTION** only for the paragraph about the argument you care about.
3. **RETURN VALUE** and **ERRORS** next — for a syscall this is where the security-relevant behaviour
   is. `ERRORS` lists every `errno` the call can produce and exactly what each means, which is how
   you turn "permission denied" into a specific diagnosis.
4. **NOTES** and **BUGS** — where the surprises are documented, including Linux-specific deviations
   from POSIX.
5. **SEE ALSO** last — the curated set of related pages, better than any search engine for this
   material.

```bash
# host / WSL — searching the manual rather than guessing page names
man -k permission          # apropos: every page whose description mentions "permission"
man -f chmod               # whatis: which sections contain a page called chmod
man 2 chmod                # the syscall, not the command
man 7 signal | less -p 'SIGQUIT'      # jump straight to a term inside a page
```

> **⚠️ Warning**
> There is **no `man` on an Android device.** Toybox has `--help` on each applet and nothing more.
> Read the manual on your laptop, then check the flag actually exists on the device with
> `toybox <cmd> --help`. This mismatch is the source of a large fraction of "the command does not
> work on the phone" confusion.

### Where to read them without a Linux machine

| Resource | Why open it |
|---|---|
| **man7.org — the Linux man-pages project** — <https://man7.org/linux/man-pages/> | The canonical, maintained HTML rendering of every page. Maintained by Michael Kerrisk. This is the one to bookmark |
| **`man 5 proc`** — <https://man7.org/linux/man-pages/man5/proc.5.html> | The field-by-field description of every file under `/proc`. Long, and worth reading in full once. The reference behind [Lab 02](../labs/lab-02-processes-proc-and-signals.md) |
| **`man 7 credentials`** — <https://man7.org/linux/man-pages/man7/credentials.7.html> | Real, effective, saved-set and filesystem UIDs, supplementary groups, and exactly which one is used for which check. The single best page for understanding Android's per-app UID model |
| **`man 7 capabilities`** — <https://man7.org/linux/man-pages/man7/capabilities.7.html> | The forty-odd fragments that root's power was divided into, and the `CapEff`/`CapPrm`/`CapBnd` bitmasks you will read out of `/proc/<pid>/status` |
| **`man 7 namespaces`** — <https://man7.org/linux/man-pages/man7/namespaces.7.html> | The seven namespace types, what each isolates, and how `/proc/<pid>/ns/` exposes them. Background for [Lab 03](../labs/lab-03-ipc-sockets-and-namespaces.md) |
| **`man 7 mount_namespaces`** — <https://man7.org/linux/man-pages/man7/mount_namespaces.7.html> | Propagation types (`shared`, `private`, `slave`), which is the mechanism behind systemless root and its DenyList |
| **`man 7 signal`** — <https://man7.org/linux/man-pages/man7/signal.7.html> | The complete signal table with default actions, plus the async-signal-safety rules that explain why crash handlers are written the way they are |
| **`man 7 unix`** — <https://man7.org/linux/man-pages/man7/unix.7.html> | UNIX-domain sockets: pathname vs abstract vs unnamed, `SO_PEERCRED`, and `SCM_RIGHTS` descriptor passing |
| **`man 7 inode`** — <https://man7.org/linux/man-pages/man7/inode.7.html> | The `st_mode` bit layout, including the setuid, setgid and sticky constants, as actual numbers |
| **`man 7 path_resolution`** — <https://man7.org/linux/man-pages/man7/path_resolution.7.html> | Precisely how the kernel walks a path, why `x` on every directory is required, and how symlinks are followed. This page explains most symlink attacks |
| **`man 2 ptrace`** — <https://man7.org/linux/man-pages/man2/ptrace.2.html> | Every request type behind debuggers, Frida attachment, and the anti-debug checks that look for them |
| **`man 2 execve`** — <https://man7.org/linux/man-pages/man2/execve.2.html> | What survives an `exec`: descriptors without `O_CLOEXEC`, the environment, and the `AT_SECURE` rules that make `LD_PRELOAD` ineffective against setuid binaries |
| **`man 2 mount`** — <https://man7.org/linux/man-pages/man2/mount.2.html> | `MS_BIND`, `MS_NOSUID`, `MS_NOEXEC`, `MS_RDONLY` — the flags you read out of `/proc/mounts` on a device |
| **`man 1 find`** — <https://man7.org/linux/man-pages/man1/find.1.html> | The `-perm` syntax specifically. `-perm 4000` and `-perm -4000` mean different things, and only one of them finds setuid binaries |

---

## 2. Books

The two that matter most are listed first. Everything after them is optional depth.

| Book | Why you would open it |
|---|---|
| **The Linux Programming Interface** — Michael Kerrisk (No Starch Press) — <https://man7.org/tlpi/> | The definitive book for this chapter and the next twenty. Written by the man-pages maintainer, so it is the same material with the explanation restored. Chapters on file permissions, process credentials, signals, pipes and FIFOs, sockets, and `/proc` map almost one-to-one onto this chapter's sections. If you buy one book for the whole repository, buy this |
| **Advanced Programming in the UNIX Environment** — W. Richard Stevens and Stephen A. Rago (Addison-Wesley) | The classic. Slightly less Linux-specific than Kerrisk and better on the *why*: process relationships, terminal handling, and the historical reasoning behind decisions that now look arbitrary |
| **How Linux Works** — Brian Ward (No Starch Press) | The gentlest genuine introduction: boot, filesystems, processes, networking, from the point of view of someone who wants to understand rather than administer. The right first book if the terminal is new to you |
| **The Linux Command Line** — William Shotts — free at <https://linuxcommand.org/tlcl.php> | Free, complete, and aimed exactly at a first-time terminal user. Work through parts 1 and 2 before Lab 01 if `cd`, `ls` and `grep` are unfamiliar |
| **UNIX and Linux System Administration Handbook** — Nemeth, Snyder, Hein, Whaley, Mackin (Addison-Wesley) | Breadth: users, permissions, filesystems, networking, logging, all with an operational mindset. The book to reach for when you need to *configure* something rather than understand it |
| **Linux Kernel Development** — Robert Love (Addison-Wesley) | When you want the kernel's side of a mechanism — the process descriptor, the VFS, signal delivery — without reading source. Dated in details, still excellent on structure |
| **Understanding the Linux Kernel** — Bovet and Cesati (O'Reilly) | Deeper and more mechanical than Love. Use as a lookup for the VFS and memory management chapters |
| **Android Security Internals** — Nikolay Elenkov (No Starch Press) | How the platform builds its security model on exactly these primitives: per-app UIDs, permissions as GIDs, keystore, and the package manager |
| **Android Internals: A Confectioner's Cookbook** — Jonathan Levin — <https://newandroidbook.com/> | Deep coverage of `init`, the `.rc` language, Zygote, the native layer and the filesystem layout. The best single source for the Android-diverges-from-Linux material in section 3.3 of the [README](../README.md) |
| **The Art of Command Line** — <https://github.com/jlevy/the-art-of-command-line> | Not a book, a single long page. Skim it once a month for the first year; you will pick up one genuinely useful idiom each time |

---

## 3. The `/proc` filesystem

`/proc` is the introspection surface for everything in this chapter and most of this repository. Four
sources, in the order you should consult them.

| Resource | Why open it |
|---|---|
| **`proc(5)` man page** — <https://man7.org/linux/man-pages/man5/proc.5.html> | Start here. Every file under `/proc` and `/proc/<pid>/`, with the meaning of each field. The `status`, `stat`, `maps`, `smaps`, `mounts` and `net/*` entries are all documented in full |
| **Kernel documentation: The `/proc` filesystem** — <https://www.kernel.org/doc/html/latest/filesystems/proc.html> | The in-tree document. More authoritative than the man page on recent additions, and the place where `smaps` field semantics and the `hidepid` mount options are explained |
| **Kernel documentation index** — <https://www.kernel.org/doc/html/latest/> | Entry point to the rest: filesystems, memory management, the admin guide, and `sysctl` knobs such as `kernel.randomize_va_space` and `vm.mmap_min_addr` |
| **`proc_pid_status` and friends in the kernel source** — `fs/proc/` in any kernel tree, browsable at <https://elixir.bootlin.com/linux/latest/source/fs/proc> | When the documentation disagrees with what you are seeing, read the function that generates the file. `fs/proc/array.c` produces `status`; `fs/proc/task_mmu.c` produces `maps` and `smaps`; `net/ipv4/tcp_ipv4.c` produces `/proc/net/tcp` |

Files worth reading the documentation for **before** you need them, because they are the ones you
will actually use:

| File | What it answers | Used in |
|---|---|---|
| `/proc/<pid>/status` | Identity, `TracerPid`, `Uid`/`Gid`, `Groups`, `CapEff`, `Seccomp`, thread count | [Lab 02](../labs/lab-02-processes-proc-and-signals.md) |
| `/proc/<pid>/maps` | Every mapped region: libraries, heaps, stacks, anonymous executable memory | Lab 02, and chapter 01's Lab 02 |
| `/proc/<pid>/fd/` | Every open file, socket, pipe and device | Labs 02 and 03 |
| `/proc/<pid>/cmdline`, `environ` | Arguments and environment, NUL-separated | Lab 02 |
| `/proc/<pid>/mounts`, `mountinfo` | The mount table **as this process sees it** — namespace-scoped | [Lab 03](../labs/lab-03-ipc-sockets-and-namespaces.md) |
| `/proc/<pid>/ns/` | Namespace identity links; two processes in the same namespace have identical inode numbers | Lab 03 |
| `/proc/net/tcp`, `tcp6`, `udp`, `unix` | Every socket, hex-encoded, with its owning UID and inode | Lab 03, and [`scripts/decode-proc-net.py`](../scripts/decode-proc-net.py) |
| `/proc/self/` | A magic symlink to the reading process — the trick that makes self-inspection possible | Everywhere |

---

## 4. POSIX, permissions and the standards

The permission model is older than Linux and is specified independently of it. When two systems
disagree about behaviour, the standard is the tie-breaker.

| Resource | Why open it |
|---|---|
| **POSIX.1-2017 / IEEE Std 1003.1** — <https://pubs.opengroup.org/onlinepubs/9699919799/> | The specification itself, free to read online. Go to *Base Definitions* chapter 4 for "File Access Permissions" — three paragraphs that define the entire `rwx`-for-owner/group/other model precisely, including the rule that the owner class is checked *instead of*, not in addition to, the group class |
| **POSIX Shell Command Language** — <https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html> | The definitive word-splitting, expansion and quoting rules. Read section 2.6 (Word Expansions) once and command-injection bugs stop being surprising |
| **`chmod(1)` in POSIX** — <https://pubs.opengroup.org/onlinepubs/9699919799/utilities/chmod.html> | The symbolic mode grammar (`u+x`, `go-w`, `a=rX`) specified exactly, including the capital-`X` rule that most people never learn |
| **`chmod(2)` man page** — <https://man7.org/linux/man-pages/man2/chmod.2.html> | The syscall, the `S_ISUID`/`S_ISGID`/`S_ISVTX` constants as numbers, and the rule that setgid is silently cleared when a non-privileged user writes to a file |
| **`man 7 inode`** — <https://man7.org/linux/man-pages/man7/inode.7.html> | The complete `st_mode` layout: file type bits in the high nibble, special bits, then the nine permission bits. This is the table to have open while doing octal arithmetic |
| **Filesystem Hierarchy Standard 3.0** — <https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html> | What `/usr`, `/var`, `/etc`, `/opt` and `/srv` are each for on a desktop distribution. Worth reading precisely so that you can see how *little* of it Android follows |
| **`acl(5)`** — <https://man7.org/linux/man-pages/man5/acl.5.html> | POSIX ACLs, the finer-grained extension to the nine bits. Included for completeness: Android does **not** use them, which is itself worth knowing when a tool reports a `+` in the mode column |
| **`umask(2)`** — <https://man7.org/linux/man-pages/man2/umask.2.html> | Why a file you created with mode `0666` came out `0644`, and why the mask is inherited across `fork()` and `execve()` |
| **`capabilities(7)`** — <https://man7.org/linux/man-pages/man7/capabilities.7.html> | The modern replacement for setuid on Linux, and the mechanism Android uses to give daemons a slice of root instead of all of it |

---

## 5. Where Android diverges from a standard Linux distribution

AOSP is browsable at <https://cs.android.com/> (Android Code Search) and
<https://android.googlesource.com/> (Gitiles). Paths below are directories and files; open them in
either viewer. Nothing here is a line number, because line numbers move.

### Identity and the sandbox

| AOSP path | Why open it |
|---|---|
| `system/core/libcutils/include/private/android_filesystem_config.h` | **The authoritative AID table.** Every named Android ID: `AID_ROOT` 0, `AID_SYSTEM` 1000, `AID_RADIO` 1001, `AID_SHELL` 2000, `AID_INET` 3003, the `AID_APP_START` 10000 range, and the isolated-process range. When you see GID 3003 on an app process and wonder why, this file is the answer |
| `system/core/libcutils/` | The C helpers that read that table, including the name-to-ID lookups used by `init` and by `ls` on device |
| `frameworks/base/core/java/android/os/Process.java` | The same constants on the Java side, plus `myUid()`, `myPid()` and the user-ID arithmetic |
| `frameworks/base/core/java/android/os/UserHandle.java` | `getUserId(uid)` and `getAppId(uid)` — the concrete implementation of `uid = userId * 100000 + appId` |
| `frameworks/base/services/core/java/com/android/server/pm/` | `PackageManagerService` and friends: where an app is assigned its UID at install time and where `packages.xml` and `packages.list` are written |

### Boot, mounts and the filesystem layout

| AOSP path | Why open it |
|---|---|
| `system/core/init/` | Android's `init`: the `.rc` parser, service management, and the property service. This is what replaces systemd, and reading it is the fastest way to understand why the device looks the way it does at boot |
| `system/core/rootdir/init.rc` | The base script: which directories are created at boot, with which owner, group and mode. When you want to know *why* `/data/local/tmp` is mode `0771` owned by `shell:shell`, the answer is a `mkdir` line in here |
| `system/core/rootdir/etc/` | The `ld.config.*.txt` linker namespace configurations — the file that decides which libraries an app is allowed to `dlopen` |
| `system/core/fs_mgr/` | Mounting logic, `dm-verity` setup, and the `fstab` handling that makes `/system` read-only and verified |
| `system/apex/` | The APEX container mechanism. This is why `libc.so` lives under `/apex/com.android.runtime/lib64/bionic/` on a modern device instead of `/system/lib64/` |

### Userspace tooling

| AOSP path | Why open it |
|---|---|
| `external/toybox/` | The multi-call binary behind almost every command on the device. When a flag does not work, read the applet here — it is usually a hundred lines and definitive |
| `external/mksh/` | `/system/bin/sh`. Read it when you need to know exactly how the device's shell performs word splitting and expansion, because that is the parser an injection payload has to survive |
| `bionic/libc/` | Android's C library. `bionic/libc/bionic/` holds the implementations; `bionic/libc/SYSCALLS.TXT` is the table from which the syscall wrappers are generated |
| `bionic/linker/` | The dynamic linker: `LD_PRELOAD` handling, the `AT_SECURE` check, and the linker-namespace enforcement that stops an app loading arbitrary system libraries |
| `system/core/libprocessgroup/` | cgroup handling for app processes — the other half of "which resources can this app use" |
| `packages/modules/adb/` | `adbd` itself: how `adb shell` gets you a pseudo-terminal, why you are UID 2000, and how `run-as` decides whether a package is debuggable |

### Policy

| AOSP path | Why open it |
|---|---|
| `system/sepolicy/` | The SELinux policy sources. `private/seapp_contexts` maps installed apps to SELinux domains and is the file that explains why two apps get different MLS categories |
| `system/sepolicy/public/` and `system/sepolicy/private/` | The `.te` files defining each domain. `untrusted_app.te` is the one that governs an ordinary app and is worth reading in full once |

### Official Android documentation

| Resource | Why open it |
|---|---|
| **Android platform documentation** — <https://source.android.com/> | The platform's own account of the security model, verified boot, SELinux, and the filesystem layout |
| **Application sandbox** — search source.android.com for "application sandbox" | The official statement of the per-UID model this chapter's primitives implement |
| **File-based encryption / Direct Boot** — search source.android.com for "file-based encryption" | Why `/data/user/` and `/data/user_de/` are separate, and what is readable before first unlock |
| **`adb` documentation** — <https://developer.android.com/tools/adb> | The full command reference, including `run-as`, `exec-out`, `forward` and `reverse` |
| **Android Debug Bridge shell commands** — <https://developer.android.com/tools/adb#shellcommands> | `pm`, `am`, `dumpsys`, `cmd` — the device-side commands that have no desktop Linux equivalent |
| **Storage and scoped storage** — <https://developer.android.com/training/data-storage> | The app-facing rules that the FUSE layer under `/sdcard` enforces |

---

## 6. Tools

| Tool | Link | Why you would reach for it |
|---|---|---|
| **Toybox** | <https://landley.net/toybox/> | The upstream project for Android's command set. The status page tells you which commands exist and how complete each is |
| **BusyBox** | <https://busybox.net/> | The alternative multi-call binary. Push a static build to `/data/local/tmp` when Toybox lacks a flag you need — never install it into `/system` |
| **strace** | <https://strace.io/> | Watch every system call a process makes. The one tool that sees through Java-level and native-level obfuscation, because a program must eventually make the syscall |
| **ltrace** | packaged as `ltrace`; `man ltrace` | Library-call tracing through the PLT, complementing `strace` |
| **`lsof`** | <https://github.com/lsof-org/lsof> | Open files and sockets across the whole system. Not on Android, where you read `/proc/<pid>/fd/` directly instead |
| **`ss` and `iproute2`** | <https://wiki.linuxfoundation.org/networking/iproute2> | The modern replacement for `netstat` and `ifconfig`. Present on newer Android builds |
| **`socat`** | <http://www.dest-unreach.org/socat/> | Connect anything to anything: FIFOs, UNIX sockets, TCP, files. The best single tool for experimenting with the IPC mechanisms in Lab 03 |
| **`nsenter`, `unshare`, `lsns`** — from util-linux | <https://github.com/util-linux/util-linux> | Enter and create namespaces from the command line. `unshare` is what Lab 03 uses to demonstrate mount-namespace separation |
| **ShellCheck** | <https://www.shellcheck.net/> | Static analysis for shell scripts. It catches unquoted expansions, which is the same bug class as command injection |
| **Explain Shell** | <https://explainshell.com/> | Paste a command line, get every flag annotated from the man pages. Genuinely useful while you are still learning to read `find` invocations |

---

## 7. Vulnerability classes referenced in this chapter

Listed by CVE identifier and one-line description. These are named in the chapter
[README](../README.md#14-references); they are repeated here with a reason to look each one up.

| Identifier | Why read about it |
|---|---|
| **CVE-2016-5195** — "Dirty COW" | A copy-on-write race in the kernel that let an unprivileged process write to read-only mappings. The canonical demonstration that a kernel bug invalidates every userspace permission check at once |
| **CVE-2015-1805** — kernel pipe iovec handling | Widely used for Android rooting. Worth reading to see how a pipe implementation detail became a privilege escalation |
| **CVE-2019-2215** — binder use-after-free | A bug in the driver that mediates almost all Android IPC. Read it alongside [24 — IPC](../../24-IPC/README.md) |
| **CVE-2022-0847** — "Dirty Pipe" | Overwriting read-only page cache through pipe buffer flags. The clearest modern example of "a file you cannot write is not necessarily a file you cannot change" |
| **CVE-2014-6271** — "Shellshock" | Bash parsing function definitions out of environment variables. The reason this chapter insists that environment inheritance is an attack surface |

> **⚠️ Warning**
> Never cite a CVE number you have not looked up. Search the identifier at
> <https://nvd.nist.gov/vuln> or <https://cve.org> and read the actual description before it goes in
> a report. A wrong CVE in a deliverable destroys your credibility faster than a missed finding.

---

## 8. Standards for the networking half

| Resource | Why open it |
|---|---|
| **RFC 9293 — Transmission Control Protocol** — <https://www.rfc-editor.org/rfc/rfc9293> | The current TCP specification (replacing RFC 793). Read section 3.3.2 for the state machine, which is what the `st` column of `/proc/net/tcp` encodes |
| **RFC 768 — User Datagram Protocol** — <https://www.rfc-editor.org/rfc/rfc768> | Three pages. Read it in full; it is the shortest way to understand what UDP does and does not promise |
| **RFC 9000 — QUIC** — <https://www.rfc-editor.org/rfc/rfc9000> | Why an app's traffic increasingly does not appear in `/proc/net/tcp` at all, and why intercepting it is harder |
| **RFC 4251–4254 — the SSH protocol** — <https://www.rfc-editor.org/rfc/rfc4251> | Architecture, transport, authentication and connection layers. Read 4254 for port forwarding, which is conceptually what `adb forward` does |
| **IANA service name and port registry** — <https://www.iana.org/assignments/service-names-port-numbers/> | The authoritative answer to "what normally runs on port N", useful when an unexpected listener turns up on a device |

---

## 9. OWASP mapping

| Identifier | Where this chapter touches it |
|---|---|
| **MASVS-STORAGE** — <https://mas.owasp.org/MASVS/> | File permissions on app data, world-readable files, and the CE/DE split |
| **MASVS-PLATFORM** | IPC endpoints: FIFOs, UNIX sockets and the `/dev/socket` daemons that predate Binder |
| **MASVS-RESILIENCE** | `TracerPid` anti-debugging, setuid-based root detection, mount-table inspection, and `/proc/self/maps` scanning |
| **MASTG** — <https://mas.owasp.org/MASTG/> | The testing procedures; the Android data-storage and anti-reversing chapters use exactly the commands in this chapter's labs |

---

## 10. Related chapters

| Chapter | What it takes from here |
|---|---|
| [01 — Computer Science Basics](../../01-Computer-Science-Basics/README.md) | The prerequisite: bits and hex (needed to decode `/proc/net/tcp`), processes, virtual memory, and system calls |
| [03 — Programming Fundamentals](../../03-Programming-Fundamentals/README.md) | What a program is, before you read any more code. The natural next chapter |
| [06 — Android Architecture](../../06-Android-Architecture/README.md) | The layered architecture and boot chain that sits on top of these primitives |
| [07 — AOSP](../../07-AOSP/README.md) | Navigating the source tree whose paths are listed in section 5 above |
| [09 — Android App Internals](../../09-Android-App-Internals/README.md) | Zygote fork and specialisation: where an app process gets its UID, umask, capabilities and SELinux label |
| [20 — Security Architecture](../../20-Security-Architecture/README.md) | The whole defence-in-depth story of which these permission bits are the first layer |
| [21 — App Sandbox](../../21-App-Sandbox/README.md) | **The direct continuation.** How per-app UIDs, permission bits and SELinux become an enforced sandbox |
| [24 — IPC](../../24-IPC/README.md) | Where classic UNIX IPC gives way to Binder and Intents, and what an attacker does with a reachable socket |
| [27 — Content Providers](../../27-ContentProviders/README.md) | The sanctioned alternative to sharing data through file permissions |
| [37 — Root Detection](../../37-RootDetection/README.md) | The applied form of setuid hunting and mount-table inspection |
| [53 — Frida](../../53-Frida/README.md) | Why `ptrace`, `TracerPid` and `/proc/self/maps` matter in practice |
| [62 — Magisk](../../62-Magisk/README.md) | Bind mounts and mount namespaces turned into systemless root and its DenyList |
| [71 — OWASP Mobile](../../71-OWASP-Mobile/README.md) | The MASVS and MASTG identifiers in section 9, in context |
| [77 — Useful Commands](../../77-UsefulCommands/README.md) | The command reference to keep open while working |
| [79 — Glossary](../../79-Glossary/README.md) | Every term in this chapter, defined once, alphabetically |

Chapters referenced in the chapter body as plain text rather than as links, and **all now
written**: [22 — SELinux](../../22-SELinux/README.md),
[23 — Permissions](../../23-Permissions/README.md), [25 — Binder](../../25-Binder/README.md),
[33 — Storage](../../33-Storage/README.md), [60 — ADB](../../60-ADB/README.md),
[67 — Bypassing Protections](../../67-BypassingProtections/README.md).
