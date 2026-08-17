# Worked Example — An Annotated `ls -l` and an Annotated `/proc/<pid>/`

Two real outputs, taken apart character by character. Nothing here is new material; it is the
material from [Lab 01](../labs/lab-01-filesystem-and-permissions.md) and
[Lab 02](../labs/lab-02-processes-proc-and-signals.md) laid out as a reference you can hold next to
your own terminal while you work.

**Chapter:** [02 — Linux Basics](../README.md) ·
[cheatsheet.md](../cheatsheet.md) ·
[permission drill](permission-arithmetic-drill.md)

> The outputs below are representative of a Pixel-class device running Android 14 with a debuggable
> test app installed. Your device's exact paths, PIDs, inode numbers and thread counts will differ.
> The *shapes* will not.

---

## Part 1 — One `ls -l` line, character by character

```bash
# adb shell
ls -l /system/bin/run-as
```

```
-rwsr-xr-x 1 root shell 76408 2024-06-01 00:00 /system/bin/run-as
```

### The whole line, exploded

```
-rwsr-xr-x   1   root   shell   76408   2024-06-01 00:00   /system/bin/run-as
└────┬───┘   │   └─┬─┘  └──┬─┘  └─┬─┘   └───────┬───────┘   └────────┬───────┘
     │       │     │       │      │             │                    │
     │       │     │       │      │             │                    └── 7. name
     │       │     │       │      │             └─────────────────────── 6. mtime
     │       │     │       │      └───────────────────────────────────── 5. size, bytes
     │       │     │       └──────────────────────────────────────────── 4. owning group
     │       │     └──────────────────────────────────────────────────── 3. owning user
     │       └────────────────────────────────────────────────────────── 2. hard link count
     └────────────────────────────────────────────────────────────────── 1. type + mode
```

### Field 1, character by character

```
 -  r  w  s     r  -  x     r  -  x
 │  └──┬──┘     └──┬──┘     └──┬──┘
 │     │           │           └───── OTHER: r-x = 4+0+1 = 5
 │     │           └───────────────── GROUP: r-x = 4+0+1 = 5
 │     └───────────────────────────── OWNER: rws → rwx with setuid = 7, plus 4000
 └─────────────────────────────────── TYPE:  - = regular file
```

Position by position:

| Pos | Char | Class | Bit | Reading |
|---|---|---|---|---|
| 1 | `-` | — | type | Regular file. `d` directory, `l` symlink, `c`/`b` device, `s` socket, `p` FIFO |
| 2 | `r` | owner | 4 | The owner may read it |
| 3 | `w` | owner | 2 | The owner may write it |
| 4 | `s` | owner | 1 + `4000` | The owner may execute it, **and the setuid bit is set**. Lower-case `s` means the underlying `x` is on; upper-case `S` would mean it is off, which is a mistake |
| 5 | `r` | group | 4 | The group may read it |
| 6 | `-` | group | 0 | The group may not write it |
| 7 | `x` | group | 1 | The group may execute it |
| 8 | `r` | other | 4 | Everyone may read it |
| 9 | `-` | other | 0 | Nobody else may write it |
| 10 | `x` | other | 1 | Everyone may execute it |

**Octal: `4755`.** Confirm rather than trust yourself:

```bash
# adb shell
stat -c '%a %A %U %G %n' /system/bin/run-as 2>/dev/null || ls -l /system/bin/run-as
```

```
4755 -rwsr-xr-x root shell /system/bin/run-as
```

### What the other six fields are telling you

**Field 2 — link count `1`.** The number of directory entries pointing at this inode. For a regular
file, `1` means exactly one name. A count above 1 means hard links exist and the "same" file is
reachable under other names. For a directory the count is 2 plus the number of subdirectories, because
every directory contains `.` (itself) and every child contains `..` (the parent).

**Field 3 — owner `root`.** The UID that owns it, shown by name. `ls -ln` shows the number instead.
On Android the name comes from a table compiled into the platform
(`system/core/libcutils/include/private/android_filesystem_config.h`), not from `/etc/passwd`, which
is why a phone's `/etc/passwd` is nearly empty and `ls -l` still prints `u0_a231`.

**Field 4 — group `shell`.** GID 2000. Combined with the mode: only members of the `shell` group get
the group bits, and everyone else falls through to `other`.

**Field 5 — size `76408`.** Bytes. For a directory this is the size of the directory structure, not
its contents. In `/proc` it is always `0`, because those files are generated on read and the
filesystem has no size to report.

**Field 6 — timestamp.** By default the *modification* time (`mtime`) — when the contents last
changed. Three timestamps exist: `mtime` (contents), `atime` (last access) and `ctime` (inode
metadata such as the mode or owner). `stat` shows all three, and `ctime` cannot be set arbitrarily,
which is occasionally useful in forensics.

**Field 7 — name.** For a symlink this becomes `name -> target`.

### Why this particular file matters

`run-as` is one of the very small number of legitimate setuid binaries on a stock Android device. It
starts as UID 0, checks whether the named package is marked debuggable, and then **drops** to that
package's UID before executing your command. That is why `adb shell run-as com.example.app id`
prints an app UID rather than `shell`.

Every part of that is visible in the line: `s` says it changes UID, `root` says which UID it changes
to, and `shell` as the group says who the platform expects to invoke it.

```bash
# adb shell — the setuid inventory, which is what root detection looks at
find /system /vendor /product /apex /sbin -perm -4000 -type f 2>/dev/null
```

On a stock device the list is short and known. `-perm -4000` with a **leading minus** means "at least
these bits"; without it, it means "exactly this mode" and matches nothing.

### The same discipline on three more lines

```bash
# adb shell
ls -ld /data /data/data /data/local/tmp
ls -l /data/app/~~kJ3nQw==/com.example.app-Xy9aBc==/base.apk
ls -ld /data/data/com.example.app
ls -l /sdcard
```

```
drwxrwx--x  49 system  system   4096 2025-08-05 09:12 /data
drwxrwx--x 180 system  system  12288 2025-08-05 09:12 /data/data
drwxrwx--x   3 shell   shell    4096 2025-08-05 09:20 /data/local/tmp
-rw-r--r--   1 system  system  8534912 2025-08-01 10:00 .../base.apk
drwx------   6 u0_a231 u0_a231  4096 2025-08-01 10:00 /data/data/com.example.app
lrw-r--r--   1 root    root       21 2009-01-01 00:00 /sdcard -> /storage/self/primary
```

| Line | Mode | The single fact that matters |
|---|---|---|
| `/data` | `771` | Other gets `x` and not `r`: traverse a known name, never enumerate |
| `/data/data` | `771` | Same. This is why you cannot list installed packages from a directory listing |
| `/data/local/tmp` | `771`, owner `shell` | Your writable, executable scratch space as UID 2000 |
| `base.apk` | `644`, owner `system` | World-readable **on purpose**. An APK is not a secret, which is why static analysis is always possible |
| `/data/data/com.example.app` | `700`, owner `u0_a231` | **This is the app sandbox.** Not an API, not a framework feature — a directory mode |
| `/sdcard` | `lrw-r--r--` | Type `l`: a symlink. Its own mode is meaningless; resolve it with `readlink -f` |

Read the third and fifth rows together and the whole Android security model is on the screen at once:
**the code is public, the data is private, and the boundary is a UID.**

---

## Part 2 — One `/proc/<pid>/` directory, entry by entry

```bash
# adb shell
PID=$(pidof com.example.app)
echo "$PID"
ls /proc/$PID/
```

```
2145
attr  cgroup  cmdline  comm  cwd  environ  exe  fd  fdinfo  limits  maps
mem  mountinfo  mounts  net  ns  oom_score  oom_score_adj  root  sched
smaps  smaps_rollup  stat  statm  status  task  wchan
```

None of those files exist on disk. `/proc` is a pseudo-filesystem: the kernel manufactures the
contents at the instant you read them. That is why every file reports size 0, why you cannot patch
one ahead of time, and why `/proc/self` resolves differently for every reader.

### `status` — the identity file, annotated

```bash
# adb shell
cat /proc/$PID/status
```

```
Name:	m.example.app          ← truncated to 15 chars, and TRIMMED FROM THE FRONT.
                                 Spoofable with prctl(PR_SET_NAME). Never trust it alone.
Umask:	0077                   ← what zygote set. New files will be 0600, directories 0700.
State:	S (sleeping)           ← S normal. R running. D stuck in I/O. Z zombie.
                                 t (tracing stop) means a debugger is attached RIGHT NOW.
Tgid:	2145                   ← thread group id — the number userspace calls "the pid"
Pid:	2145                   ← kernel task id. For a thread this differs from Tgid.
PPid:	483                    ← the parent. This is zygote64. Anything else is unusual.
TracerPid:	0                  ← ★ THE anti-debugging field. Non-zero names the tracer.
Uid:	10231	10231	10231	10231
                               ← real, effective, saved-set, FILESYSTEM.
                                 File permission checks use the fourth one.
                                 All four equal = nothing clever is happening.
Gid:	10231	10231	10231	10231
FDSize:	256                    ← allocated slots, not the number open. A big value hints
                                 at a descriptor leak.
Groups:	3003 9997 20231 50231  ← ★ 3003 = AID_INET. The INTERNET permission IS this group.
                                 Remove it and the app cannot open a socket, with no
                                 framework involvement at all.
Threads:	42                 ← an idle Android app still has dozens
SigBlk:	0000000000001000
SigIgn:	0000000000000000
SigCgt:	2000000e400084f8       ← hex bitmask of signals with handlers installed.
                                 Bit N-1 = signal N. A SIGSEGV (11) handler means a crash
                                 reporter, a packer, or anti-tamper code.
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000       ← ★ all zeros: this process holds NO capabilities.
CapBnd:	0000000000000000         Correct for an app. Anything else is privileged.
NoNewPrivs:	1                  ← it can never gain privileges through a setuid binary
Seccomp:	2                  ← ★ 2 = a syscall filter is installed. Normal for an app.
                                 A blocked syscall raises SIGSYS (31), not EPERM.
```

The five starred lines are, collectively, the enforcement state of the Android sandbox for this
process: which UID, which supplementary groups, which capabilities, which syscall filter, and whether
anyone is debugging it. Everything
[21 — App Sandbox](../../21-App-Sandbox/README.md) describes is visible here as numbers.

```bash
# adb shell — the fields worth grepping, every time
grep -E '^(Name|State|PPid|TracerPid|Uid|Gid|Groups|Threads|CapEff|Seccomp)' /proc/$PID/status
```

### `cmdline` and `environ` — and the NUL problem

```bash
# adb shell — the confusing version
cat /proc/$PID/cmdline; echo
```

```
com.example.app
```

That looks fine because there is only one argument. Try PID 1:

```bash
# adb shell
cat /proc/1/cmdline; echo
tr '\0' '\n' < /proc/1/cmdline
xxd /proc/1/cmdline | head -2
```

```
/system/bin/initsecond_stage
/system/bin/init
second_stage
00000000: 2f73 7973 7465 6d2f 6269 6e2f 696e 6974  /system/bin/init
00000010: 0073 6563 6f6e 645f 7374 6167 6500        .second_stage.
```

The `00` bytes in the hex dump are the separators. The kernel stores `argv` as NUL-terminated strings
laid end to end — lossless, because an argument containing a space stays one argument — and the
terminal draws NUL as nothing. `tr '\0' '\n'` makes it readable.

The same applies to `environ`:

```bash
# adb shell
tr '\0' '\n' < /proc/$PID/environ
```

```
PATH=/product/bin:/apex/com.android.runtime/bin:/system/bin:/system_ext/bin
ANDROID_ROOT=/system
ANDROID_DATA=/data
ANDROID_ART_ROOT=/apex/com.android.art
ANDROID_I18N_ROOT=/apex/com.android.i18n
ANDROID_TZDATA_ROOT=/apex/com.android.tzdata
EXTERNAL_STORAGE=/sdcard
BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:...
```

An app's environment is short and dull, because it is inherited from Zygote. **That is what makes
anomalies loud.** An app process carrying `LD_PRELOAD`, an unusual `LD_LIBRARY_PATH`, or a debug
variable has been tampered with or was started unusually.

```bash
# adb shell — the one-liner worth memorising
tr '\0' '\n' < /proc/$PID/environ | grep -i -E 'token|key|secret|password|debug|preload'
```

`grep` may refuse these files outright with `Binary file matches`, because they contain bytes below
0x20. Use `grep -a`, or translate with `tr` first.

### The four magic symlinks

```bash
# adb shell
ls -l /proc/$PID/exe /proc/$PID/cwd /proc/$PID/root
```

```
lrwxrwxrwx 1 u0_a231 u0_a231 0 2025-08-05 13:10 /proc/2145/exe  -> /system/bin/app_process64
lrwxrwxrwx 1 u0_a231 u0_a231 0 2025-08-05 13:10 /proc/2145/cwd  -> /
lrwxrwxrwx 1 u0_a231 u0_a231 0 2025-08-05 13:10 /proc/2145/root -> /
```

| Link | What it proves |
|---|---|
| `exe` | The **real** executable, by inode — not the name the process advertises. Note it is `app_process64`, not the package: every app is a specialised fork of Zygote, and the binary on disk is the same one for all of them. Still resolves after the file is deleted, with a ` (deleted)` suffix |
| `cwd` | Where relative paths resolve from. Also a *reference*, so it still reaches a directory that a later mount has covered — which is [Lab 04](../labs/lab-04-ctf-the-hidden-flag.md) stage 5 |
| `root` | The process's root directory. Anything other than `/` means it has been `chroot`ed or is in a container |

### `fd/` — everything the process has open

```bash
# adb shell
ls -l /proc/$PID/fd | head -20
ls -l /proc/$PID/fd | wc -l
```

```
lrwx------ 1 u0_a231 u0_a231 64 ... 0 -> /dev/null
lrwx------ 1 u0_a231 u0_a231 64 ... 1 -> /dev/null
lrwx------ 1 u0_a231 u0_a231 64 ... 2 -> /dev/null
lrwx------ 1 u0_a231 u0_a231 64 ... 4 -> anon_inode:[eventpoll]
lrwx------ 1 u0_a231 u0_a231 64 ... 5 -> /dev/binder
lrwx------ 1 u0_a231 u0_a231 64 ... 6 -> anon_inode:[eventfd]
lr-x------ 1 u0_a231 u0_a231 64 ... 12 -> /data/app/~~kJ3nQw==/com.example.app-Xy9aBc==/base.apk
lrwx------ 1 u0_a231 u0_a231 64 ... 19 -> /data/data/com.example.app/databases/app.db
lrwx------ 1 u0_a231 u0_a231 64 ... 20 -> /data/data/com.example.app/databases/app.db-wal
lrwx------ 1 u0_a231 u0_a231 64 ... 27 -> socket:[184213]
lr-x------ 1 u0_a231 u0_a231 64 ... 31 -> /data/data/com.example.app/cache/tmp8412 (deleted)
```

| Line | What to do about it |
|---|---|
| `0`, `1`, `2` → `/dev/null` | Normal for an app: stdout and stderr go nowhere, which is why `System.out.println` does not appear in logcat |
| `/dev/binder` | Every app has one. This is the framework IPC channel — [24 — IPC](../../24-IPC/README.md) |
| `anon_inode:[eventpoll]`, `[eventfd]` | The Looper's message queue. Normal |
| `base.apk` | Held open for resource loading. Normal |
| `app.db`, `app.db-wal` | **Pull these.** An open SQLite database is where session state lives |
| `socket:[184213]` | Cross-reference the inode against `/proc/net/tcp` — [Lab 03](../labs/lab-03-ipc-sockets-and-namespaces.md) |
| `... (deleted)` | **Read it.** The file has no name anywhere on the filesystem and the data is still there: `cat /proc/$PID/fd/31`. Apps do this to temporary decrypted content constantly |

```bash
# adb shell — the two highest-yield one-liners against an app's descriptors
ls -l /proc/$PID/fd | grep deleted
ls -l /proc/$PID/fd | sed -n 's/.*socket:\[\([0-9]*\)\].*/\1/p'
```

### `task/` — the threads

```bash
# adb shell
ls /proc/$PID/task/ | wc -l
for t in /proc/$PID/task/*/comm; do
  printf '%s  %s\n' "$(basename "$(dirname "$t")")" "$(cat "$t")"
done | head -14
```

```
42
2145  m.example.app
2151  Jit thread pool
2152  HeapTaskDaemon
2153  ReferenceQueueD
2154  FinalizerDaemon
2155  FinalizerWatchd
2156  Profile Saver
2158  Binder:2145_1
2159  Binder:2145_2
2160  Binder:2145_3
2171  RenderThread
2180  queued-work-loo
2191  OkHttp Connecti
2203  pool-3-thread-1
```

That list is a fingerprint. `Binder:<pid>_N` threads serve incoming IPC. `Jit thread pool`,
`HeapTaskDaemon` and `ReferenceQueueD` are ART's. `OkHttp Connecti...` tells you the HTTP client
before you have decompiled a single class. And a thread called `gum-js-loop`, `gmain` or
`pool-frida-*` means an instrumentation engine is inside the process — which is one of the cheapest
Frida-detection checks in existence, and one you can run yourself.

### `mounts` and `ns/` — is this process seeing the same filesystem you are?

```bash
# adb shell
readlink /proc/$PID/ns/mnt
readlink /proc/self/ns/mnt
readlink /proc/1/ns/mnt
diff <(cat /proc/self/mounts) <(cat /proc/$PID/mounts) | head
```

```
mnt:[4026532310]
mnt:[4026531841]
mnt:[4026531841]
```

Two processes are in the same mount namespace **if and only if** those inode numbers match. Here the
app is in its own namespace and your shell is in init's. On a stock device that is normal — the
storage subsystem gives apps their own view of `/storage`. On a device with systemless root and a
DenyList, it is also how the app is shown a filesystem with the modifications removed.

An unprivileged app can read its own `ns/mnt` and cannot read anyone else's, and has no baseline to
compare against. That asymmetry is why namespace-based hiding defeats every on-device file check.
[Lab 03 Part E](../labs/lab-03-ipc-sockets-and-namespaces.md) and
[62 — Magisk](../../62-Magisk/README.md).

### The rest, in one table

| Entry | Read it when |
|---|---|
| `stat` | You are scripting. Same data as `status`, as 52 unlabelled space-separated fields. Field 3 is the state letter |
| `statm` | You want memory in pages, as seven numbers, cheaply |
| `maps`, `smaps`, `smaps_rollup` | You are looking at memory layout — covered in [chapter 01's Lab 02](../../01-Computer-Science-Basics/labs/lab-02-processes-memory-maps.md) |
| `mem` | You are dumping memory. Needs `ptrace` privilege |
| `limits` | You suspect descriptor exhaustion, or want to know about core dumps |
| `cgroup` | You care about scheduling — Android puts foreground apps in `top-app` |
| `oom_score_adj` | You want to know how likely the low-memory killer is to take this process |
| `wchan` | The process is stuck and you want to know in which kernel function |
| `attr/current` | You need the SELinux domain, e.g. `u:r:untrusted_app:s0:c231,c256,c512,c768` |
| `net/` | The process is in its own network namespace and `/proc/net/*` would show you the wrong tables |
| `fdinfo/N` | You need a descriptor's current offset and open flags, not just its target |

---

## Part 3 — The triage sequence, in the order you would actually run it

```bash
# adb shell — a complete first pass over one app, about ninety seconds
PKG=com.example.app
PID=$(pidof $PKG)

# 1. identity and enforcement state
grep -E '^(Name|State|PPid|TracerPid|Uid|Gid|Groups|Threads|CapEff|Seccomp)' /proc/$PID/status
cat /proc/$PID/attr/current; echo

# 2. what it is, really
ls -l /proc/$PID/exe /proc/$PID/cwd
tr '\0' '\n' < /proc/$PID/cmdline

# 3. what it is carrying
tr '\0' '\n' < /proc/$PID/environ | grep -iE 'token|key|secret|preload|debug'

# 4. what it has open -- databases, sockets, and deleted files
ls -l /proc/$PID/fd | grep -E 'databases|shared_prefs|deleted|socket'

# 5. who it is talking to
UID=$(cmd package list packages -U | grep "^package:$PKG " | sed 's/.*uid://')
awk -v u="$UID" 'NR>1 && $8==u' /proc/net/tcp /proc/net/tcp6

# 6. is it in a different filesystem view than I am
readlink /proc/$PID/ns/mnt; readlink /proc/self/ns/mnt

# 7. a free thread dump of whatever it is doing right now
kill -3 $PID && sleep 1 && logcat -d | grep -A40 "Cmd line: $PKG" | head -50
```

Every step of that is one of the files annotated above. Run it against
[`../scripts/first-shell.sh`](../scripts/first-shell.sh) for the environment side, and
[`../scripts/decode-proc-net.py`](../scripts/decode-proc-net.py) for step 5's hex.

---

## Where this goes next

| Next | Why |
|---|---|
| [Lab 01](../labs/lab-01-filesystem-and-permissions.md) | Derive Part 1 yourself on a real device |
| [Lab 02](../labs/lab-02-processes-proc-and-signals.md) | Derive Part 2, and watch `TracerPid` change live |
| [Lab 03](../labs/lab-03-ipc-sockets-and-namespaces.md) | The socket inode and the namespace inode, in full |
| [Permission drill](permission-arithmetic-drill.md) | Field 1 until it is automatic |
| [21 — App Sandbox](../../21-App-Sandbox/README.md) | Where the `Uid`, `Groups`, `CapEff` and `Seccomp` values come from |
| [37 — Root Detection](../../37-RootDetection/README.md) | The same files, read by the app instead of by you |
