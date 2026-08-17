# 02 — Linux Basics · Cheat Sheet

Printable. Tables and commands only. Full explanations in [README.md](README.md).

---

## Navigation and files

| Task | Command |
|---|---|
| Where am I | `pwd` |
| Change directory | `cd /data/local/tmp` · `cd ..` · `cd -` (previous) |
| List | `ls` · `ls -l` · `ls -la` · `ls -lh` · `ls -lt` (by time) · `ls -lS` (by size) |
| List a directory itself | `ls -ld /data/data` |
| Tree | `find . -type d` (no `tree` on device) |
| Make directory | `mkdir -p a/b/c` |
| Copy / move / delete | `cp -r src dst` · `mv a b` · `rm -rf dir` |
| Read a file | `cat f` · `head -20 f` · `tail -20 f` · `tail -f f` |
| File type | `file base.apk` |
| Size of a tree | `du -sh dir` |
| Free space | `df -h` |
| Hard link / symlink | `ln target name` · `ln -s target name` |
| Resolve a symlink | `readlink -f path` |
| Timestamps | `stat file` |

## Permissions

| Octal | Bits | Meaning |
|---|---|---|
| 7 | rwx | read + write + execute |
| 6 | rw- | read + write |
| 5 | r-x | read + execute |
| 4 | r-- | read only |
| 1 | --x | traverse only (directories) |
| 0 | --- | none |

| Special bit | Octal | Symbol | Effect |
|---|---|---|---|
| setuid | 4000 | `s` in owner-x | Run with the file owner's euid |
| setgid | 2000 | `s` in group-x | Run with file group's egid; dirs propagate group |
| sticky | 1000 | `t` in other-x | Only owners may delete entries in the directory |

| Mode | Where |
|---|---|
| `0700` | `/data/data/<pkg>` |
| `0600` | SharedPreferences, SQLite |
| `0644` | `base.apk` |
| `0755` | `/system/bin/*` |
| `1777` | `/data/local/tmp`, `/tmp` |
| `4755` | classic setuid `su` |

| Task | Command |
|---|---|
| Change mode | `chmod 0700 f` · `chmod u+s f` · `chmod -R 0750 d` |
| Change owner | `chown user:group f` · `chown -R system:system d` |
| Show/set umask | `umask` · `umask 077` |
| Find setuid files | `find / -perm -4000 -type f 2>/dev/null` |
| Find world-writable | `find / -perm -o+w -type f 2>/dev/null` |

## Identity

| Task | Command |
|---|---|
| My identity | `id` |
| Effective uid only | `id -u` |
| A process's identity | `grep -E 'Uid\|Gid\|Groups' /proc/<pid>/status` |
| Capabilities | `grep Cap /proc/<pid>/status` |
| SELinux context | `cat /proc/<pid>/attr/current` · `id -Z` |
| SELinux mode | `getenforce` |

| AID | Value |
|---|---|
| root | 0 |
| system | 1000 |
| radio | 1001 |
| log | 1007 |
| wifi | 1010 |
| adb | 1011 |
| media_rw | 1023 |
| shell | 2000 |
| inet (INTERNET permission) | 3003 |
| net_raw | 3004 |
| readproc | 3009 |
| nobody | 9999 |
| apps | 10000–19999 |
| shared gid | 50000–59999 |
| isolated | 99000–99999 |
| per-user offset | 100000 |

`uid = userId * 100000 + appId`

## Processes

| Task | Command |
|---|---|
| All processes | `ps -A` · `ps -A -o USER,PID,PPID,NAME` |
| With threads | `ps -A -T` |
| Find a PID | `pidof com.example.app` |
| Live view | `top -b -n1` |
| Kill | `kill <pid>` · `kill -9 <pid>` · `pkill -f pattern` |
| Java thread dump | `kill -3 <pid>` then read logcat |
| Suspend / resume | `kill -STOP <pid>` · `kill -CONT <pid>` |
| Background survive shell exit | `nohup cmd >/dev/null 2>&1 &` |

| State | Meaning |
|---|---|
| R | running/runnable |
| S | interruptible sleep |
| D | uninterruptible sleep (I/O) |
| T | stopped (SIGSTOP) |
| t | tracing stop (debugger) |
| Z | zombie |

## `/proc`

| Path | Contents |
|---|---|
| `/proc/<pid>/status` | Uid, Gid, Groups, **TracerPid**, CapEff, Seccomp, Threads |
| `/proc/<pid>/maps` | Every mapping: libraries, heaps, anon rwx |
| `/proc/<pid>/smaps_rollup` | Total Rss/Pss quickly |
| `/proc/<pid>/fd/` | One symlink per open file/socket |
| `/proc/<pid>/cmdline` | argv, NUL-separated |
| `/proc/<pid>/environ` | envp, NUL-separated |
| `/proc/<pid>/exe` | The running binary |
| `/proc/<pid>/cwd` | Working directory |
| `/proc/<pid>/mounts` | Mount table **for that namespace** |
| `/proc/<pid>/task/` | Per-thread directories |
| `/proc/<pid>/limits` | RLIMIT values |
| `/proc/mounts` | Caller's mount namespace |
| `/proc/net/tcp`, `tcp6`, `udp`, `unix` | Sockets with owning UID + inode |
| `/proc/version`, `/proc/cpuinfo` | Kernel and CPU fingerprint |

```bash
tr '\0' ' ' < /proc/<pid>/cmdline; echo
tr '\0' '\n' < /proc/<pid>/environ
```

`/proc/net/tcp` address decoding: `0100007F:69A2` = `127.0.0.1:27042` (bytes reversed, port in hex).

## Signals

| # | Name | Catchable | Use |
|---|---|---|---|
| 2 | SIGINT | yes | Ctrl-C |
| 3 | SIGQUIT | yes | **ART Java thread dump** |
| 5 | SIGTRAP | yes | Breakpoint / single step |
| 6 | SIGABRT | yes | `abort()`, Bionic fatal |
| 9 | SIGKILL | **no** | Immediate death |
| 11 | SIGSEGV | yes | Invalid memory → tombstone |
| 15 | SIGTERM | yes | Polite exit (default of `kill`) |
| 17 | SIGCHLD | yes | Child exited |
| 19 | SIGSTOP | **no** | Unconditional suspend |
| 31 | SIGSYS | yes | seccomp violation |

## Streams, redirection, pipes

| Syntax | Effect |
|---|---|
| `> f` / `>> f` | stdout to file / append |
| `2> f` | stderr to file |
| `> f 2>&1` | both to file (order matters) |
| `< f` | file as stdin |
| `2>/dev/null` | discard errors |
| `a \| b` | stdout of a → stdin of b |
| `a && b` / `a \|\| b` | run b on success / failure |
| `$(cmd)` | substitute output |
| `cmd \| tee f` | copy to file and onward |

## Text tools

```bash
grep -rn "pattern" dir/          grep -riE "(key|secret|token)" .
grep -rl "str" .                 grep -o 'https\?://[^" ]*' f
sed 's/a/b/g' f                  sed -i 's/a/b/g' f
sed -n '10,20p' f                sed -n '/BEGIN/,/END/p' f
awk '{print $2}' f               awk -F: '{print $1,$3}' f
awk '$1 ~ /^u0_a/ {print $2}' f  awk '{s+=$1} END {print s}' f
find . -name "*.so" -type f      find . -perm -4000 2>/dev/null
find . -print0 | xargs -0 grep -l "x"
cut -d: -f1 f                    sort -u f       sort -n f
uniq -c                          tr '\0' '\n' < f
strings -n 8 lib.so              xxd -l 64 f      od -A x -t x1z f
base64 -d < f                    sha256sum f
```

## Networking

| Task | Command |
|---|---|
| Listening sockets | `netstat -tulpn` · `ss -tulpn` |
| Raw tables | `cat /proc/net/tcp` · `/proc/net/tcp6` · `/proc/net/unix` |
| Interfaces | `ip addr` · `ifconfig` |
| Routes | `ip route` |
| Firewall | `iptables -L -n -v` · `iptables -t nat -L -n -v` |
| Block QUIC to force TCP | `iptables -A OUTPUT -p udp --dport 443 -j REJECT` |
| Capture | `tcpdump -i any -s0 -w /data/local/tmp/c.pcap` |

## ADB

```bash
adb devices -l                       adb -s <serial> shell
adb root                             adb remount
adb push local /data/local/tmp/      adb pull /path ./
adb install -r -t app.apk            adb uninstall <pkg>
adb logcat -c ; adb logcat -v time   adb logcat -d > log.txt
adb shell pm list packages -3 -U     adb shell pm path <pkg>
adb shell pm clear <pkg>             adb shell pm grant <pkg> <perm>
adb shell dumpsys package <pkg>      adb shell dumpsys meminfo <pkg>
adb shell am start -n <pkg>/.Main    adb shell am start -a VIEW -d "scheme://x"
adb forward tcp:27042 tcp:27042      adb reverse tcp:8080 tcp:8080
adb shell run-as <pkg> ls -la
adb exec-out "run-as <pkg> tar cf - ." > data.tar
adb bugreport bug.zip                adb shell screencap -p /sdcard/s.png
```

## Android filesystem

| Path | Contents |
|---|---|
| `/system`, `/system_ext`, `/product` | Read-only platform, dm-verity |
| `/vendor`, `/odm` | HALs, firmware, vendor init |
| `/apex/com.android.runtime` | Bionic: libc.so, linker64 |
| `/apex/com.android.art` | libart.so, dex2oat |
| `/data/app/~~x~~/<pkg>-y/base.apk` | Installed APK |
| `/data/data/<pkg>` = `/data/user/0/<pkg>` | CE private storage, mode 0700 |
| `/data/user_de/0/<pkg>` | DE storage, readable before first unlock |
| `/data/system/packages.xml`, `packages.list` | Package DB |
| `/data/local/tmp` | shell-writable (1777) |
| `/data/media/<user>` | Backing store for `/sdcard` |
| `/data/misc/keystore`, `/data/misc/adb/adb_keys` | Keys |
| `/data/tombstones`, `/data/anr` | Crash and ANR artefacts |
| `/dev/socket/*` | Native daemon sockets |

## Environment and linker

| Variable | Meaning |
|---|---|
| `PATH` | Command search path |
| `LD_LIBRARY_PATH` | Extra library search dirs |
| `LD_PRELOAD` | Libraries loaded first — symbol interposition |
| `BOOTCLASSPATH` | ART boot class path |
| `ANDROID_DATA` / `ANDROID_ROOT` | `/data` / `/system` |

```bash
export V=x            V=x ./prog            unset V
setprop wrap.<pkg> "LD_PRELOAD=/data/local/tmp/libhook.so"   # debuggable apps only
```

`LD_PRELOAD` is ignored for `AT_SECURE` (setuid/capability) binaries, and has no effect on Zygote-forked apps.

## Namespaces and mounts

```bash
cat /proc/self/mounts | grep -Ei 'magisk|overlay|tmpfs'
diff <(cat /proc/1/mounts) <(cat /proc/$(pidof <pkg>)/mounts)   # non-empty = separate namespace
mount --bind /src /dst              umount /dst
unshare --mount sh                  nsenter --target 1 --mount --pid -- sh
```

## Shell scripting quick reference

```sh
#!/system/bin/sh
set -eu
VAR="value"; N=$(( 1 + 2 )); OUT=$(cmd)
if [ -f "$f" ]; then ...; elif [ -d "$d" ]; then ...; else ...; fi
for x in a b c; do echo "$x"; done
while [ "$i" -lt 5 ]; do i=$(( i + 1 )); done
cmd | while read -r line; do echo "$line"; done
fn() { echo "$1"; }
# tests: -e -f -d -r -w -x -z -n  =  !=  -eq -ne -lt -le -gt -ge
# args: $0 $1..$9 $# $@ $?
```

## Toybox vs GNU gotchas

| GNU | On Android |
|---|---|
| `grep -P` | unsupported |
| `find -printf` | unsupported |
| `xargs -0` | may be missing |
| `ls --color=auto` | may be rejected |
| `stat -c` | different specifiers |
| `bash` | absent; use `sh` (mksh) |
| `[[ ]]`, arrays | avoid |

Push a static BusyBox: `adb push busybox /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/busybox`
