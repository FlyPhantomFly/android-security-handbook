# Annotated Zygote Fork Trace

**What this is:** an annotated `strace` of Zygote forking an app process, mapping every syscall to the
step in `SpecializeCommon()` described in [README §4.3](../README.md#43-trace-two-an-app-launch-through-zygote).

**Why it matters:** the app sandbox is not a document — it is this specific sequence of syscalls,
executed in this specific order. Watching it once makes the security model concrete in a way no
diagram achieves.

---

## Capturing it yourself

```bash
# adb shell as root — attach to the right Zygote for the app's ABI
ZPID=$(pidof -s zygote64)
strace -f -tt \
  -e trace=clone,fork,setuid,setgid,setgroups,setresuid,setresgid,capset,prctl,seccomp,mount,unshare,openat,write \
  -p $ZPID -o /data/local/tmp/zygote.trace
```

```bash
# host — in another terminal, launch the target
adb shell am start -n com.example.target/.MainActivity
```

```bash
# host
adb pull /data/local/tmp/zygote.trace
```

> **Note.** `strace` is not present on stock builds. Push a static build to `/data/local/tmp`, or use
> a `userdebug` AOSP image. Perfetto with the `ftrace` syscall data source is an alternative that
> needs no extra binary.

---

## The trace, annotated

The output below is representative and lightly cleaned — timestamps and irrelevant syscalls removed —
but the **order** is faithful.

```text
# ---------------------------------------------------------------------------
# PHASE 1 — Zygote is idle in runSelectLoop(), blocked on its socket.
# ---------------------------------------------------------------------------

[pid  1893] 14:22:31.104 accept4(9, {sa_family=AF_UNIX}, [2], SOCK_CLOEXEC) = 24
```
`ZygoteServer.runSelectLoop()` has woken. `ActivityManagerService` connected to `/dev/socket/zygote`
and is about to send the fork request. See [README §4.3 step 2](../README.md).

```text
[pid  1893] 14:22:31.106 read(24, "16\n--runtime-args\n--setuid=10247\n"
                              "--setgid=10247\n--runtime-flags=2049\n"
                              "--mount-external-full\n--target-sdk-version=34\n"
                              "--setgroups=3003,9997,20247,50247\n"
                              "--nice-name=com.example.target\n"
                              "--seinfo=default:targetSdkVersion=34:complete\n"
                              "--instruction-set=arm64-v8a\n"
                              "--app-data-dir=/data/user/0/com.example.target\n"
                              "android.app.ActivityThread\n", 4096) = 402
```

**This is the entire sandbox specification, in one message.** Read it field by field:

| Argument | Meaning |
|---|---|
| `--setuid=10247` / `--setgid=10247` | The app's UID, allocated by `PackageManagerService` |
| `--setgroups=3003,...` | Supplementary GIDs. **3003 is `AID_INET`** — this app holds `INTERNET` |
| `--seinfo=default:targetSdkVersion=34` | Feeds `seapp_contexts` to pick the SELinux domain |
| `--target-sdk-version=34` | Drives compatibility behaviour **and** the `untrusted_app_XX` variant |
| `--runtime-flags=2049` | A bitmask: debuggable, JIT settings, and more |
| `--mount-external-full` | The external-storage mount-namespace mode |
| `--nice-name` | The process name you see in `ps` |
| `android.app.ActivityThread` | The entry point the child will run |

> **Pentester's Note**
> Everything the sandbox will be is decided by `system_server` **before** the fork and sent as text.
> The app has no say in it. This is why `PackageManagerService` is the authority on app identity, and
> why a bug there is far more serious than a bug in Zygote itself.

```text
# ---------------------------------------------------------------------------
# PHASE 2 — Pre-fork housekeeping, in the PARENT.
# ---------------------------------------------------------------------------

[pid  1893] 14:22:31.108 openat(AT_FDCWD, "/proc/self/fd", O_RDONLY|O_DIRECTORY) = 25
[pid  1893] 14:22:31.109 getdents64(25, ...) = 512
```
`FileDescriptorTable` enumerates open FDs. Zygote must know exactly which descriptors exist so the
child does not silently inherit something it should not — a leaked FD across the fork would be a
sandbox hole.

```text
[pid  1893] 14:22:31.110 write(4, "\1\0\0\0\0\0\0\0", 8) = 8
```
Stopping ART's daemon threads before forking. `fork()` only clones the calling thread, so any thread
holding a lock at fork time would leave that lock permanently held in the child. This is
`PreApplicationInit` doing its job.

```text
# ---------------------------------------------------------------------------
# PHASE 3 — THE FORK.
# ---------------------------------------------------------------------------

[pid  1893] 14:22:31.112 clone(child_stack=NULL,
                               flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD) = 14206
```

**This is the moment.** PID 14206 is the new app process. It currently has:

- root's UID and GID
- every capability Zygote holds
- **no** seccomp filter
- Zygote's SELinux domain
- **Zygote's exact address-space layout** ← the ASLR consequence from [README §5.4](../README.md)

Everything from here happens **in the child**, and every step reduces privilege.

```text
# ---------------------------------------------------------------------------
# PHASE 4 — SpecializeCommon(). Read this phase carefully; it IS the sandbox.
# ---------------------------------------------------------------------------

[pid 14206] 14:22:31.113 prlimit64(0, RLIMIT_NOFILE, {rlim_cur=32768, rlim_max=32768}, NULL) = 0
```
**Step 1: resource limits.** Bounds what the process can exhaust.

```text
[pid 14206] 14:22:31.114 unshare(CLONE_NEWNS)            = 0
[pid 14206] 14:22:31.115 mount("/mnt/user/0/emulated", "/storage/emulated", NULL, MS_BIND|MS_REC, NULL) = 0
```
**Mount namespace.** The child gets its own view of external storage. This is why one app cannot see
another's `Android/data` directory even on shared storage — the mount table differs per app. See
[33-Storage](../../33-Storage/README.md).

```text
[pid 14206] 14:22:31.117 setgroups(4, [3003, 9997, 20247, 50247]) = 0
```
**Step 2: supplementary groups.** GID 3003 is `AID_INET`. **This is the moment the `INTERNET`
permission becomes real** — it is not a framework check at all, it is a Linux group that lets the
process create network sockets. An app without `INTERNET` does not have 3003 here, and
`socket()` fails in the kernel.

```text
[pid 14206] 14:22:31.118 setresgid(10247, 10247, 10247) = 0
[pid 14206] 14:22:31.119 setresuid(10247, 10247, 10247) = 0
```
**Step 3: drop to the app identity.** Note the order — **GID before UID**. Once you `setresuid` away
from root you can no longer change the GID, so getting this backwards would leave the process with
root's group. This ordering is a classic privilege-dropping requirement and getting it wrong is a
well-known bug class in Unix software generally.

```text
[pid 14206] 14:22:31.120 capset({version=_LINUX_CAPABILITY_VERSION_3, pid=0},
                                {effective=0, permitted=0, inheritable=0}) = 0
```
**Step 4: drop all capabilities.** This is why `CapEff` on an app process must read
`0000000000000000`. Anything else means the process did not come through this path.

```text
[pid 14206] 14:22:31.121 prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) = 0
```
**Step 5: `NO_NEW_PRIVS`.** Privilege can now **never** be regained — not via a setuid binary, not via
file capabilities, not by any means. It is a one-way latch, and it must be set before the seccomp
filter (unprivileged seccomp requires it).

```text
[pid 14206] 14:22:31.122 seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=182, filter=0x...}) = 0
```
**Step 6: the seccomp-bpf filter.** 182 BPF instructions generated from the allow-lists in
`bionic/libc/seccomp/`. This removes the large portion of the kernel syscall surface apps never
legitimately need — which is exactly the surface a sandbox escape would otherwise have to work with.
This is what `Seccomp: 2` in `/proc/<pid>/status` reports.

```text
[pid 14206] 14:22:31.123 openat(AT_FDCWD, "/proc/self/attr/current", O_WRONLY) = 26
[pid 14206] 14:22:31.124 write(26, "u:r:untrusted_app_34:s0:c247,c256,c512,c768", 43) = 43
```
**Step 7: the SELinux context.** `selinux_android_setcontext()` uses the `seinfo` string from the
request and the `seapp_contexts` mapping to choose the domain.

Note the two parts:
- `untrusted_app_34` — the domain, chosen by `targetSdkVersion`
- `c247,c256,c512,c768` — **MCS categories**, which give per-app isolation *within* the shared domain

Without those categories, every untrusted app would be in the same domain and type enforcement alone
would not separate them. See [22-SELinux](../../22-SELinux/README.md).

```text
[pid 14206] 14:22:31.125 prctl(PR_SET_NAME, "ple.target")   = 0
```
**Step 8: the process name.** Truncated to 15 characters by the kernel — which is why long package
names appear cut off in `ps`.

```text
# ---------------------------------------------------------------------------
# PHASE 5 — The child becomes an app.
# ---------------------------------------------------------------------------

[pid 14206] 14:22:31.130 openat(AT_FDCWD, "/data/user/0/com.example.target", O_RDONLY|O_DIRECTORY) = 27
```
The app data directory, now accessible because the process holds the right UID.

```text
[pid 14206] 14:22:31.145 openat(AT_FDCWD, "/data/app/~~xyz==/com.example.target-abc==/base.apk", O_RDONLY) = 30
[pid 14206] 14:22:31.152 mmap(NULL, 8317440, PROT_READ, MAP_SHARED, 30, 0) = 0x7b40000000
```
The APK is mapped. `RuntimeInit.applicationInit()` is about to invoke `ActivityThread.main()`.

```text
[pid 14206] 14:22:31.203 ioctl(6, BINDER_WRITE_READ, ...) = 0
```
The child Binders **back into** `system_server` to announce itself. Note the direction: the new
process calls the server, not the other way round. This handshake is why an app that hangs in a static
initialiser shows "process started but never attached", and why `ActivityManagerService` has a timeout
for exactly that case. See [README §4.3 step 6](../README.md).

---

## Verify the outcome

```bash
# adb shell
PID=$(pidof -s com.example.target)
cat /proc/$PID/status | grep -E '^(Uid|Gid|Groups|CapEff|Seccomp|NoNewPrivs):'
cat /proc/$PID/attr/current
```

Expected, and now explicable line by line:

```text
Uid:        10247   10247   10247   10247      ← setresuid
Gid:        10247   10247   10247   10247      ← setresgid
Groups:     3003 9997 20247 50247              ← setgroups (3003 = INTERNET)
CapEff:     0000000000000000                   ← capset
Seccomp:    2                                  ← seccomp(SECCOMP_SET_MODE_FILTER)
NoNewPrivs: 1                                  ← prctl(PR_SET_NO_NEW_PRIVS)

u:r:untrusted_app_34:s0:c247,c256,c512,c768    ← write to /proc/self/attr/current
```

---

## What to take from this

1. **The sandbox is a syscall sequence, not a policy document.** Nine operations, in a specific order,
   executed in the child immediately after `fork()`.

2. **The order is load-bearing.** GID before UID; `NO_NEW_PRIVS` before seccomp; capabilities dropped
   before any app code runs. Each is a correctness requirement, not a style choice.

3. **`system_server` decides everything before the fork.** The app has no input into its own sandbox.
   That is why `PackageManagerService` is the real authority on app identity.

4. **`INTERNET` is a Linux group.** GID 3003. Not a framework check — a kernel-enforced group
   membership. That is why it cannot be granted or revoked at runtime like a dangerous permission.

5. **The child inherits Zygote's address space.** Which is the ASLR weakness in
   [README §5.4](../README.md), and it follows directly from `clone()` rather than `execve()`.

6. **Any deviation is a signal.** Non-empty `CapEff`, `Seccomp: 0`, or a missing MCS category on an app
   process means it did not come through this path. Worth investigating immediately.
