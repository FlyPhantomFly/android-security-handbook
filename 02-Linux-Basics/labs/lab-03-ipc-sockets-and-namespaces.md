# Lab 03 — IPC, Sockets and Mount Namespaces

> After this lab you will be able to make two unrelated processes talk to each other through three
> different UNIX mechanisms, decode a hex-encoded little-endian address and port out of
> `/proc/net/tcp` **on paper**, trace any socket back to the process that owns it, and give a process
> a completely different — and completely genuine — view of the filesystem using a bind mount inside
> its own mount namespace.

**Chapter:** [02 — Linux Basics](../README.md)
**Difficulty:** Advanced
**Estimated time:** 4 hours
**Prerequisite labs:** [Lab 01 — Filesystem and permissions](lab-01-filesystem-and-permissions.md)
and [Lab 02 — Processes, `/proc` and signals](lab-02-processes-proc-and-signals.md). You need to be
comfortable with modes, `/proc/<pid>/fd/` and `ls -l` before starting.

---

## Objective

Two processes are isolated by default. That is the point of the process boundary. But isolated
processes are useless, so every operating system provides mechanisms for them to communicate, and
every one of those mechanisms is an authorisation decision: *who is allowed to talk to whom, and how
does the receiver know who is speaking?*

That question is the whole of this lab, and it is the question that Binder was invented to answer
properly on Android. You cannot appreciate why Binder exists until you have used the mechanisms it
replaced and felt where they are weak.

The second half of the lab is about a different kind of lie: **mount namespaces**. A process can be
shown a filesystem that is entirely real, entirely consistent, and entirely different from what its
neighbour sees. Nothing is faked at the API level; the kernel is telling the truth about a different
view. This is the mechanism behind systemless root, behind Android's per-app storage views, and
behind every container you have ever heard of.

By the end you will have:

- Created a FIFO and passed data through it between two unrelated shells, and demonstrated that its
  permission bits decide who may participate.
- Created a UNIX-domain socket, connected to it, and read the peer's credentials from the kernel.
- Explained what an abstract-namespace socket is and why it has no permissions at all.
- **Decoded a full line of `/proc/net/tcp` by hand, on paper, with no tools** — address, port, state,
  UID and inode.
- Traced a socket inode back to the owning process through `/proc/<pid>/fd/`.
- Checked your hand-decoding against [`../scripts/decode-proc-net.py`](../scripts/decode-proc-net.py).
- Created a bind mount and shown that one path now serves another path's contents.
- Entered a new mount namespace, unmounted something *inside it only*, and proved from outside that
  the original mount still exists.
- Compared `/proc/<pid>/ns/mnt` inode numbers to prove two processes are in different namespaces.
- Explained, in your own words, why an app cannot detect a namespace-based hide by reading files.

> **📖 Definition — Inter-process communication (IPC)**
> Any mechanism by which two processes exchange data or synchronise, given that they have separate
> address spaces and cannot touch each other's memory. Every mechanism must answer three questions:
> how the endpoints find each other, who is authorised to connect, and how the receiver learns who
> the sender is.

---

## Prerequisites

| Requirement | Why | Check |
|---|---|---|
| Linux, WSL 2, or a Linux VM | Parts A–D need real UNIX IPC; Part E needs namespaces | `ls /proc/self/ns/` |
| `sudo` on that machine | Bind mounts and `unshare` need privilege | `sudo -v` |
| `socat` and `python3` | Building endpoints without writing C | `which socat python3` |
| An Android device or emulator | Parts C and F | `adb devices` |
| Root on the device, or `adb root` on a non-Play emulator | Reading another process's `fd/` | `adb shell id` |

```bash
# host / WSL — install what is missing
sudo apt update && sudo apt install -y socat python3 util-linux iproute2
```

> **⚠️ Warning**
> Part E creates and destroys mounts. Every mount in this lab is inside `~/lab03` or
> `/tmp/lab03`, is created with an explicit source and target you type yourself, and is unmounted in
> Part G. Do not experiment with bind mounts over `/etc`, `/usr` or `/`. A stray
> `mount --bind /tmp /etc` on a running system is a very bad afternoon.
>
> On a **device**, do not create mounts at all unless it is your own test device. Modifying the mount
> table of a client's phone is not a read-only action and does not belong in an assessment.

---

## Setup

```bash
# host / WSL
mkdir -p ~/lab03 && cd ~/lab03
pwd
```

```bash
# adb shell — device-side scratch
mkdir -p /data/local/tmp/lab03
cd /data/local/tmp/lab03
```

You will need **three terminals** on the host for most of this lab. Open them now and label them
mentally: T1, T2, T3.

---

## Steps

### Part A — Pipes and FIFOs

**A1. The anonymous pipe you already use.**

```bash
# host / WSL — T1
ls -l /usr/bin | grep python
```

The `|` created a pipe: a kernel buffer with a read end and a write end, handed to the two processes
as file descriptors. The shell pointed `ls`'s descriptor 1 at the write end and `grep`'s descriptor 0
at the read end.

> **📖 Definition — Pipe**
> A unidirectional in-kernel byte buffer (64 KiB by default on Linux) created by the `pipe()`
> syscall, which returns two descriptors. The writer blocks when the buffer is full; the reader
> blocks when it is empty. When the last writer closes, the reader sees end-of-file. When the last
> reader closes, the writer receives `SIGPIPE`.

An anonymous pipe has no name, so only processes that inherited the descriptors — a parent and its
children — can use it. That is the limitation the FIFO removes.

**A2. Create a FIFO — a pipe with a name.**

```bash
# host / WSL — T1
cd ~/lab03
mkfifo mypipe
ls -l mypipe
stat -c '%F %a %n' mypipe
```

```
prw-r--r-- 1 harsh harsh 0 Aug  5 14:00 mypipe
fifo 644 mypipe
```

The type character is `p`. The size is 0 and always will be — a FIFO is not storage, it is a
rendezvous point. The permission bits are ordinary file permissions and they are what decides who may
open it for reading and who for writing.

**A3. Use it between two unrelated shells.**

In T1:

```bash
# host / WSL — T1 — this blocks until a writer appears
cd ~/lab03
cat mypipe
```

In T2:

```bash
# host / WSL — T2
cd ~/lab03
echo "hello from terminal 2" > mypipe
```

T1 immediately prints:

```
hello from terminal 2
```

and then `cat` exits, because the last writer closed and the reader saw end-of-file.

**A4. Watch the blocking behaviour.** Reverse the order — start the writer first:

```bash
# host / WSL — T2
echo "writer first" > mypipe
```

Nothing happens. The `echo` is blocked, because opening a FIFO for writing blocks until a reader
opens it. Now in T1:

```bash
# host / WSL — T1
cat mypipe
```

Both unblock at once. A FIFO is a synchronisation point as much as a data channel.

**A5. Inspect it from `/proc` while it is open.** In T1:

```bash
# host / WSL — T1
cat mypipe &
CATPID=$!
sleep 1
ls -l /proc/$CATPID/fd
```

```
lr-x------ 1 harsh harsh 64 Aug  5 14:05 0 -> /home/harsh/lab03/mypipe
lrwx------ 1 harsh harsh 64 Aug  5 14:05 1 -> /dev/pts/1
```

The FIFO shows up as an ordinary file path, because that is what it is. Compare with an anonymous
pipe, which shows as `pipe:[184213]` with an inode number and no path at all.

```bash
# host / WSL — T2
sleep 300 | cat &
sleep 1
for p in $(jobs -p); do echo "--- $p"; ls -l /proc/$p/fd 2>/dev/null | grep pipe; done
```

**A6. Permissions decide participation.**

```bash
# host / WSL — T1
chmod 600 mypipe
ls -l mypipe
```

Now only you can read or write it. Set it to `666` and any process on the system, running as any
user, can inject data into whatever is reading. That is the whole security model of a FIFO: file
permissions, and nothing else. The reader has no way to find out who wrote the bytes.

> **🔍 Pentester's Note**
> A world-writable FIFO in a shared directory is a message-injection channel. On Android this turns
> up in apps that bundle a native daemon and use a FIFO under `/data/data/<pkg>/` or, far worse,
> under `/data/local/tmp` or shared storage, to talk to it. Look for `mkfifo` in decompiled native
> code and for `p` type characters when you list an app's directories:
> `run-as com.example.app find . -type p`.

**A7. On the device.**

```bash
# adb shell
cd /data/local/tmp/lab03
mkfifo devpipe
ls -l devpipe
# T1 on the device (or a second adb shell)
cat devpipe &
echo "from the device shell" > devpipe
```

---

### Part B — UNIX-domain sockets

A FIFO gives you a byte stream with file permissions. A UNIX-domain socket gives you the same, plus
three things a FIFO cannot do: bidirectional communication, **kernel-attested peer credentials**, and
**file descriptor passing**.

**B1. Create a socket endpoint with `socat`.** In T1:

```bash
# host / WSL — T1 — a server that echoes what it receives, in upper case
cd ~/lab03
socat UNIX-LISTEN:mysock,fork EXEC:'tr a-z A-Z'
```

In T2:

```bash
# host / WSL — T2
cd ~/lab03
ls -l mysock
echo "hello unix socket" | socat - UNIX-CONNECT:mysock
```

```
srwxr-xr-x 1 harsh harsh 0 Aug  5 14:15 mysock
HELLO UNIX SOCKET
```

The type character is `s`. Like a FIFO, the file is a rendezvous point with ordinary permission bits;
unlike a FIFO, the connection is bidirectional and the kernel knows who connected.

**B2. Peer credentials — the thing that makes UNIX sockets different.**

> **📖 Definition — `SO_PEERCRED`**
> A socket option on a connected UNIX-domain socket that returns a `struct ucred` containing the PID,
> UID and GID of the process at the other end, **as recorded by the kernel at connect time**. The
> peer cannot lie about it. There is no equivalent for a FIFO, and no equivalent for a plain TCP
> socket.

Demonstrate it. Write a tiny server that prints the credentials of whoever connects:

```bash
# host / WSL — T1 — save this, then run it
cat > ~/lab03/credserver.py <<'PYEOF'
#!/usr/bin/env python3
"""Print the kernel-attested credentials of every process that connects."""
import os, socket, struct, sys

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credsock")
if os.path.exists(PATH):
    os.unlink(PATH)

srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(PATH)
os.chmod(PATH, 0o666)          # deliberately permissive, to make the point
srv.listen(5)
print("listening on", PATH, "-- Ctrl+C to stop")

try:
    while True:
        conn, _ = srv.accept()
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                              struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
        print(f"connection from pid={pid} uid={uid} gid={gid}")
        conn.sendall(f"I know you are pid {pid}, uid {uid}\n".encode())
        conn.close()
finally:
    srv.close()
    if os.path.exists(PATH):
        os.unlink(PATH)
PYEOF
python3 ~/lab03/credserver.py
```

In T2:

```bash
# host / WSL — T2
socat - UNIX-CONNECT:$HOME/lab03/credsock
```

T1 prints:

```
connection from pid=49102 uid=1000 gid=1000
```

T2 receives:

```
I know you are pid 49102, uid 1000
```

The client never sent its PID or UID. The kernel supplied them. **This is unforgeable**, and it is
the basis of authorisation in almost every native Android daemon that listens on a socket.

**B3. Why this matters on Android.** Look at the sockets that exist on a real device:

```bash
# adb shell
ls -l /dev/socket/
```

```
srw-rw---- 1 root   system    0 2025-08-05 09:11 adbd
srw-rw---- 1 root   root      0 2025-08-05 09:11 property_service
srw-rw---- 1 root   system    0 2025-08-05 09:11 zygote
srw-rw---- 1 root   root      0 2025-08-05 09:11 logdw
srw-rw-rw- 1 root   root      0 2025-08-05 09:11 dnsproxyd
...
```

Read those modes. `property_service` is `srw-rw----` owned by `root:root` — only root may connect.
`zygote` is `root:system`. `dnsproxyd` is `srw-rw-rw-` — world-connectable, because every app needs
DNS resolution, and its authorisation therefore *must* come from `SO_PEERCRED` or SELinux rather than
from the mode.

> **🔍 Pentester's Note**
> The triage question for any `/dev/socket` entry is not "what is its mode" but "**given that
> `untrusted_app` can reach it, does the daemon check who is calling?**" A daemon running as root
> that accepts a command over a `0666` socket and does not call `getsockopt(SO_PEERCRED)` is a
> privilege escalation. This is a recurring pattern in OEM and vendor code, and it is exactly the
> attack surface that [24 — IPC](../../24-IPC/README.md) develops. This lab teaches you the
> mechanism; that chapter teaches you what to do with it.

**B4. Abstract-namespace sockets — the ones with no permissions at all.**

A Linux extension lets a UNIX socket be bound to a name in an *abstract namespace* rather than to a
filesystem path. The name starts with a NUL byte, which is conventionally written as `@` by tools.
Because there is no file, **there are no permission bits**.

```bash
# host / WSL — list them
cat /proc/net/unix | head -20
```

```
Num       RefCount Protocol Flags    Type St Inode Path
0000...: 00000002 00000000 00010000 0001 01 184213 /run/systemd/private
0000...: 00000002 00000000 00010000 0001 01 184901 @/tmp/dbus-AbCdEf
```

The entry starting with `@` is abstract. Anything that can create a socket can connect to it — the
only possible authorisation is `SO_PEERCRED` or SELinux.

```bash
# adb shell — abstract sockets on a device
cat /proc/net/unix | grep '@' | head -20
```

Android uses abstract sockets in several places, and a daemon that binds one and does not check its
peer is reachable from every app on the device. What an attacker does with that is
[24 — IPC](../../24-IPC/README.md)'s territory; what it *is* is this lab's.

**B5. Descriptor passing, in one paragraph.** A UNIX socket can carry a file descriptor from one
process to an unrelated one, using a control message of type `SCM_RIGHTS`. The receiving process gets
a working descriptor for the same open file — with the access rights that were checked at the
original `open()`, not re-checked against the receiver's identity. That is the mechanism behind
`ParcelFileDescriptor` on Android and behind a whole class of privilege-crossing bugs. You do not
need to implement it here; you need to know that a descriptor in `/proc/<pid>/fd/` may have arrived
from somewhere other than an `open()` by that process.

---

### Part C — Decoding `/proc/net/tcp` by hand

**This is the highest-value half hour in the chapter.** Do it on paper. Do not run the decoder script
until you have finished.

**C1. Get a line to decode.** Start a listener so there is something interesting:

```bash
# host / WSL — T1
python3 -m http.server 8080 --bind 127.0.0.1
```

```bash
# host / WSL — T2
cat /proc/net/tcp
```

```
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 184213 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:B3C6 01 00000000:00000000 00:00000000 00000000  1000        0 184260 1 0000000000000000 20 4 30 10 -1
```

**C2. The columns.**

| Column | Name | Meaning |
|---|---|---|
| 1 | `sl` | Slot number in the kernel's hash table. Meaningless to you |
| 2 | `local_address` | **Local IP and port, as `IIIIIIII:PPPP` in hex** |
| 3 | `rem_address` | Remote IP and port, same encoding. All zeros for a listener |
| 4 | `st` | **TCP state, in hex** |
| 5 | `tx_queue:rx_queue` | Bytes queued for send and receive |
| 6 | `tr:tm->when` | Timer type and expiry |
| 7 | `retrnsmt` | Retransmit count |
| 8 | `uid` | **The UID that created the socket** — in decimal |
| 9 | `timeout` | Unanswered probe count |
| 10 | `inode` | **The socket's inode number** — the link back to a process |

**C3. Decode the address, step by step.**

Take `0100007F`. That is eight hex digits, which is four bytes:

```
0100007F   →   01  00  00  7F
```

Those four bytes are the 32-bit IPv4 address as it sits in memory on a **little-endian** machine —
that is, least significant byte first. To get the dotted-quad, **reverse the byte order**:

```
01 00 00 7F   reversed   →   7F 00 00 01
```

Now convert each byte from hex to decimal:

```
0x7F = 127
0x00 = 0
0x00 = 0
0x01 = 1
```

which gives **127.0.0.1**.

**C4. Decode the port.** Take `1F90`. That is four hex digits, two bytes — and here is the trap that
catches everyone the first time:

> **⚠️ Warning**
> **The address is byte-reversed. The port is not.** The kernel prints the port in network byte
> order, which is big-endian, so you read it straight. `1F90` is `0x1F90`, not `0x901F`.

```
0x1F90 = 1 * 4096 + 15 * 256 + 9 * 16 + 0
       = 4096 + 3840 + 144 + 0
       = 8080
```

So `0100007F:1F90` is **127.0.0.1:8080** — which is exactly the listener you started in C1.

**C5. Decode the state.** Take `0A`. TCP states are a small enumeration, in hex:

| Hex | State | What it means |
|---|---|---|
| `01` | `ESTABLISHED` | A live connection carrying data |
| `02` | `SYN_SENT` | We sent a SYN and are waiting |
| `03` | `SYN_RECV` | We received a SYN and replied |
| `04` | `FIN_WAIT1` | We started closing |
| `05` | `FIN_WAIT2` | Our close was acknowledged |
| `06` | `TIME_WAIT` | Waiting out stray packets after close |
| `07` | `CLOSE` | Closed |
| `08` | `CLOSE_WAIT` | The peer closed; we have not yet |
| `09` | `LAST_ACK` | We closed after the peer did |
| `0A` | **`LISTEN`** | **A server socket waiting for connections** |
| `0B` | `CLOSING` | Both sides closed simultaneously |

`0A` is `LISTEN`. Combined with C3 and C4: something is listening on 127.0.0.1:8080.

**C6. Put the whole line together.** Line 0 from C1:

```
0: 0100007F:1F90 00000000:0000 0A ... 1000 0 184213
   └────┬─────┘  └────┬─────┘  └┬┘     └┬┘   └──┬──┘
        │             │         │       │       └── inode 184213
        │             │         │       └────────── uid 1000
        │             │         └────────────────── state 0A = LISTEN
        │             └──────────────────────────── remote 0.0.0.0:0 (none — it is listening)
        └────────────────────────────────────────── local 127.0.0.1:8080
```

**Reading:** UID 1000 has a socket listening on 127.0.0.1 port 8080, and its inode is 184213.

Now line 1:

```
1: 0100007F:1F90 0100007F:B3C6 01 ... 1000 0 184260
```

Local is the same 127.0.0.1:8080. Remote is `0100007F` = 127.0.0.1 and port `B3C6`:

```
0xB3C6 = 11 * 4096 + 3 * 256 + 12 * 16 + 6
       = 45056 + 768 + 192 + 6
       = 46022
```

State `01` = `ESTABLISHED`. So: an established connection from 127.0.0.1:46022 to 127.0.0.1:8080,
owned by UID 1000. That is a browser or a `curl` talking to your Python server.

**C7. Practise on five lines, cold.** Decode each of these completely — local address and port,
remote address and port, state, and what it probably is. Write your answers before looking.

```
 0: 0100007F:69A2 00000000:0000 0A ...  2000 0 297431
 1: 00000000:15B3 00000000:0000 0A ...     0 0 102944
 2: 3500007F:0035 00000000:0000 0A ..  1051 0 118203
 3: A02BA8C0:C1B2 5DB8D8AD:01BB 01 ... 10231 0 448210
 4: 0100007F:1F90 0100007F:E1D4 06 ...  1000 0 452911
```

<details>
<summary>Answers</summary>

**Line 0** — `0100007F` reversed is `7F 00 00 01` = 127.0.0.1. Port `69A2` = 6*4096 + 9*256 + 10*16 +
2 = 24576 + 2304 + 160 + 2 = **27042**. State `0A` = LISTEN. UID **2000** = `shell`.
**This is `frida-server` listening on its default port, started from an adb shell.** It is precisely
what a Frida-detection routine looks for.

**Line 1** — `00000000` = 0.0.0.0, meaning *all interfaces*, which is far more exposed than
localhost. Port `15B3` = 1*4096 + 5*256 + 11*16 + 3 = 4096 + 1280 + 176 + 3 = **5555**. State LISTEN.
UID **0** = root. **This is `adbd` listening for wireless debugging on every interface** — a serious
exposure if it was left on.

**Line 2** — `3500007F` reversed is `7F 00 00 35` = **127.0.0.53**. Port `0035` = **53**. State
LISTEN. A local DNS stub resolver. (Note how the `35` appears in both the address and the port here
by coincidence — a good reason to decode carefully rather than pattern-match.)

**Line 3** — `A02BA8C0` reversed is `C0 A8 2B A0` = **192.168.43.160**. Port `C1B2` = 12*4096 +
1*256 + 11*16 + 2 = 49152 + 256 + 176 + 2 = **49586**. Remote `5DB8D8AD` reversed is
`AD D8 B8 5D` = **173.216.184.93**. Port `01BB` = 1*256 + 11*16 + 11 = 256 + 176 + 11 = **443**.
State `01` = ESTABLISHED. UID **10231** — an ordinary app. **An app is talking HTTPS to an external
host.** The UID tells you exactly which app.

**Line 4** — 127.0.0.1:8080 to 127.0.0.1, port `E1D4` = 14*4096 + 1*256 + 13*16 + 4 = 57344 + 256 +
208 + 4 = **57812**. State `06` = TIME_WAIT: a connection that has finished and is waiting out stray
packets.

</details>

**C8. Trace a socket back to its process.** This is the payoff. The `inode` column is the same number
that appears in `/proc/<pid>/fd/`.

```bash
# host / WSL — take an inode from your own /proc/net/tcp
INODE=184213
for p in /proc/[0-9]*; do
  if ls -l "$p/fd" 2>/dev/null | grep -q "socket:\[$INODE\]"; then
    echo "inode $INODE belongs to PID ${p##*/}: $(cat $p/comm)"
  fi
done
```

```
inode 184213 belongs to PID 49055: python3
```

On Android, the same technique with the UID column narrows it immediately:

```bash
# adb shell
cat /proc/net/tcp | awk 'NR>1 {print $2, $3, $4, $8, $10}'
# then, for an interesting inode:
INODE=448210
for p in /proc/[0-9]*; do ls -l $p/fd 2>/dev/null | grep -q "socket:\[$INODE\]" && echo "$p"; done
```

```bash
# adb shell — or go straight from UID to package
cmd package list packages --uid 10231
```

**C9. IPv6, in one step more.** `/proc/net/tcp6` uses 32 hex digits — sixteen bytes — printed as
**four 32-bit words, each individually byte-reversed**. Reverse each group of eight hex digits
separately, then join.

```
00000000000000000000000001000000
└──w0──┘└──w1──┘└──w2──┘└──w3──┘

w0 00000000 → 00 00 00 00
w1 00000000 → 00 00 00 00
w2 00000000 → 00 00 00 00
w3 01000000 → 00 00 00 01

bytes: 00 00 ... 00 01   =   ::1
```

An IPv4-mapped address looks like this:

```
0000000000000000FFFF00000100007F
w0 = 0, w1 = 0, w2 FFFF0000 → 00 00 FF FF, w3 0100007F → 7F 00 00 01
bytes: :: ffff 7f 00 00 01   =   ::ffff:127.0.0.1
```

**C10. Now check yourself with the script.**

```bash
# host / WSL
python3 ../scripts/decode-proc-net.py /proc/net/tcp
python3 ../scripts/decode-proc-net.py /proc/net/tcp6
```

```bash
# host — decode a device's tables without pushing anything
adb shell cat /proc/net/tcp  > tcp.txt
adb shell cat /proc/net/tcp6 > tcp6.txt
python3 ../scripts/decode-proc-net.py tcp.txt tcp6.txt
```

```
FILE: /proc/net/tcp   (IPv4)
   LOCAL                  REMOTE                 STATE        UID    INODE
   127.0.0.1:8080         0.0.0.0:0              LISTEN      1000   184213
   127.0.0.1:8080         127.0.0.1:46022        ESTABLISHED 1000   184260
```

The script exists so you can *verify* your arithmetic, not replace it. On a device with no Python and
no tooling — which happens — you will decode by hand, and you can.

> **🔍 Pentester's Note**
> Everything you just did, a hardened app can do to you. `/proc/net/tcp` is world-readable, so an app
> can scan it from inside its own sandbox with no permissions at all, looking for a listener on 27042
> (Frida), 23946 (IDA), or 5555 (adb over TCP). Running `frida-server -l 127.0.0.1:1337` changes the
> port; a thorough check enumerates every listener and probes each with the Frida handshake. The
> escalation from here is chapter 67 — Bypassing Protections.

---

### Part D — What Binder does that none of this does

Before moving on, write down the comparison. You have now used the mechanisms Android chose to
replace.

| Property | FIFO | UNIX socket | TCP socket | Binder |
|---|---|---|---|---|
| Naming | Filesystem path | Path, or abstract name | IP and port | Service name in `servicemanager` |
| Authorisation | File permission bits | Permission bits (none if abstract), plus SELinux | Firewall and UID rules | SELinux plus explicit `checkCallingPermission` |
| Caller identity | **None. The reader cannot know who wrote** | `SO_PEERCRED` — kernel-attested, if the daemon asks | None without a protocol-level scheme | **Always available**, kernel-attested, via `Binder.getCallingUid()` and `getCallingPid()` |
| Copies of the data | Two (write to kernel, read from kernel) | Two | Two | **One** |
| Passing descriptors | No | Yes, `SCM_RIGHTS` | No | Yes, `ParcelFileDescriptor` |
| Object references | No | No | No | Yes — remote objects with reference counting |
| Death notification | Only end-of-file | Only end-of-file | Only reset | Yes, `linkToDeath` |
| Thread management | Yours | Yours | Yours | A managed thread pool per process |

Read the "caller identity" row again. It is the single reason Binder exists. With a FIFO, the
receiver *cannot* know who sent the bytes; with a UNIX socket it can, but only if the developer
remembered to ask; with Binder the caller's UID is always available and always true. Every Android
permission check ultimately rests on that fact.

Classic IPC has not disappeared from Android. It survives in the `/dev/socket` daemons, in FIFOs
inside app sandboxes, and in shared memory. That surviving surface is where the interesting native
bugs are, which is exactly why this lab exists.
[24 — IPC](../../24-IPC/README.md) takes it from here.

---

### Part E — Bind mounts and mount namespaces

Now the second half: making one process see a different filesystem from another, without lying to it.

**E1. What a bind mount is.**

> **📖 Definition — Bind mount**
> A mount that makes an existing directory or file appear at a second location in the tree. Both
> paths then refer to the same underlying inodes; it is not a copy and not a symlink. The original
> contents of the mount point are hidden — not deleted — for as long as the mount exists.

```bash
# host / WSL
mkdir -p ~/lab03/real ~/lab03/mountpoint
echo "I am the REAL file"   > ~/lab03/real/data.txt
echo "I am the HIDDEN file" > ~/lab03/mountpoint/data.txt

cat ~/lab03/mountpoint/data.txt
sudo mount --bind ~/lab03/real ~/lab03/mountpoint
cat ~/lab03/mountpoint/data.txt
```

```
I am the HIDDEN file
I am the REAL file
```

The path `~/lab03/mountpoint/data.txt` now serves different content, and nothing about the file at
that path was modified. Confirm it is a mount, not magic:

```bash
# host / WSL
grep lab03 /proc/mounts
findmnt ~/lab03/mountpoint
ls -i ~/lab03/real/data.txt ~/lab03/mountpoint/data.txt
```

```
/dev/sdc /home/harsh/lab03/mountpoint ext4 rw,relatime,discard,errors=remount-ro 0 0
```

The two paths report the **same inode number**, because they are the same file.

**E2. Undo it and prove the hidden file survived.**

```bash
# host / WSL
sudo umount ~/lab03/mountpoint
cat ~/lab03/mountpoint/data.txt
```

```
I am the HIDDEN file
```

Nothing was ever destroyed. That property — *hide, do not modify* — is the entire basis of systemless
root: the real partition is untouched, so `dm-verity` and Verified Boot remain satisfied.

**E3. Mount namespaces.** So far the bind mount was visible to every process on the machine. A
**mount namespace** makes a mount visible to only some of them.

> **📖 Definition — Namespace**
> A kernel mechanism that gives a set of processes their own instance of a global resource. Linux has
> seven kinds: **mount** (`mnt`), **process IDs** (`pid`), **network** (`net`), **IPC** (`ipc`),
> **hostname** (`uts`), **users** (`user`) and **cgroup**. A process in a different mount namespace
> has its own mount table; changes it makes are not seen by processes in other namespaces.

Look at yours:

```bash
# host / WSL
ls -l /proc/self/ns/
```

```
lrwxrwxrwx 1 harsh harsh 0 Aug  5 14:40 cgroup -> 'cgroup:[4026531835]'
lrwxrwxrwx 1 harsh harsh 0 Aug  5 14:40 ipc -> 'ipc:[4026531839]'
lrwxrwxrwx 1 harsh harsh 0 Aug  5 14:40 mnt -> 'mnt:[4026531841]'
lrwxrwxrwx 1 harsh harsh 0 Aug  5 14:40 net -> 'net:[4026531840]'
lrwxrwxrwx 1 harsh harsh 0 Aug  5 14:40 pid -> 'pid:[4026531836]'
lrwxrwxrwx 1 harsh harsh 0 Aug  5 14:40 user -> 'user:[4026531837]'
lrwxrwxrwx 1 harsh harsh 0 Aug  5 14:40 uts -> 'uts:[4026531838]'
```

Those numbers are namespace identities. **Two processes are in the same namespace if and only if
these inode numbers match.** That is the comparison you will make in E6.

**E4. Enter a new mount namespace.** First set up a mount that is visible everywhere:

```bash
# host / WSL — T1
sudo mount --bind ~/lab03/real ~/lab03/mountpoint
cat ~/lab03/mountpoint/data.txt      # "I am the REAL file"
grep -c lab03 /proc/mounts           # 1
```

Now, in T2, create a new mount namespace and remove the mount **inside it only**:

```bash
# host / WSL — T2
sudo unshare --mount /bin/bash
# you are now root in a NEW mount namespace
echo "namespace shell pid $$"
grep -c lab03 /proc/mounts           # 1  -- inherited a copy of the table
umount /home/harsh/lab03/mountpoint
grep -c lab03 /proc/mounts           # 0  -- gone, here
cat /home/harsh/lab03/mountpoint/data.txt
```

```
namespace shell pid 49510
1
0
I am the HIDDEN file
```

**Now look at T1, which is still in the original namespace:**

```bash
# host / WSL — T1
grep -c lab03 /proc/mounts           # 1  -- still there
cat ~/lab03/mountpoint/data.txt      # "I am the REAL file"
```

Two shells, on the same machine, at the same instant, reading the same path, getting different
content. **Neither is being deceived.** Each is reading its own genuine mount table and resolving the
path through it.

**E5. This is exactly how systemless root hiding works.** Read the sequence and match it to what you
just did:

1. Magisk never writes to `/system`. It builds an alternative view with **bind mounts**, so the real
   partition and its `dm-verity` hashes are untouched — that is what "systemless" means.
2. When a process on the DenyList is forked from Zygote, Magisk calls `unshare(CLONE_NEWNS)` in the
   child, giving it a **private mount namespace**.
3. Inside that namespace only, it **unmounts its own modifications**.
4. The app then reads `/proc/self/mounts` and sees a clean table. It calls `stat("/system/xbin/su")`
   and genuinely gets `ENOENT`. It walks `/system/bin` and genuinely finds nothing added.

Nothing is hooked. No API returns a fabricated value. The kernel answers truthfully about a different
namespace — which is why this defeats every file-existence and mount-table check, and why root
detection has to move to attestation. [62 — Magisk](../../62-Magisk/README.md) and
[37 — Root Detection](../../37-RootDetection/README.md) develop this fully.

**E6. Prove the two shells are in different namespaces.**

In the T2 namespace shell:

```bash
# host / WSL — T2, inside unshare
readlink /proc/self/ns/mnt
echo "my pid is $$"
```

```
mnt:[4026532451]
my pid is 49510
```

In T1:

```bash
# host / WSL — T1
readlink /proc/self/ns/mnt
readlink /proc/49510/ns/mnt
```

```
mnt:[4026531841]
mnt:[4026532451]
```

Different inode numbers, therefore different namespaces. This comparison is the *only* reliable way
to detect namespace separation, and it needs privilege to read another process's `ns/` — which an
ordinary app does not have. That asymmetry is the whole reason namespace hiding wins against
on-device checks.

Leave the namespace shell with `exit`. The namespace is destroyed when the last process in it exits,
and its mounts go with it.

**E7. On Android.** Do not create mounts on a device you do not own. Reading is fine:

```bash
# adb shell — how many distinct mount namespaces exist right now?
for p in /proc/[0-9]*; do readlink $p/ns/mnt 2>/dev/null; done | sort | uniq -c | sort -rn | head
```

```
    198 mnt:[4026531841]
      3 mnt:[4026532310]
      1 mnt:[4026532387]
```

Most processes share the init namespace. The outliers are worth investigating: on a device with
Magisk and a DenyList, the DenyList'ed apps have their own. On a stock device, the storage subsystem
creates per-user namespaces for the `/storage` views.

```bash
# adb shell — compare an app's mount table with the shell's
PID=$(pidof com.android.settings)
diff <(cat /proc/self/mounts) <(cat /proc/$PID/mounts) | head -20
```

Differences here are normal — the storage bind mounts differ per app. Learning what normal looks like
is the point.

---

### Part F — Put it together on a device

**F1. Full socket triage of one app.**

```bash
# adb shell
PKG=com.example.app
PID=$(pidof $PKG)
UID=$(cmd package list packages -U | grep "^package:$PKG " | sed 's/.*uid://')
echo "pkg=$PKG pid=$PID uid=$UID"

echo "--- its sockets, by descriptor"
ls -l /proc/$PID/fd | grep socket

echo "--- its TCP connections, by UID"
awk -v u="$UID" 'NR>1 && $8==u' /proc/net/tcp
awk -v u="$UID" 'NR>1 && $8==u' /proc/net/tcp6

echo "--- its UNIX sockets"
grep -f <(ls -l /proc/$PID/fd | sed -n 's/.*socket:\[\([0-9]*\)\].*/\1/p') /proc/net/unix
```

Decode each TCP line by hand using Part C, then confirm with the script. You should be able to say,
for each connection: which host and port, in which state, and — because you have the UID — which
installed package opened it.

**F2. Any FIFOs or sockets inside the app's sandbox?**

```bash
# adb shell — for a debuggable app
run-as $PKG find . -type p -o -type s 2>/dev/null
run-as $PKG ls -la . 
```

A `p` or `s` entry inside an app's private directory means the app runs a helper process and talks to
it over classic IPC. Check the mode. If it is world-anything, that is a channel another app can join.

---

### Part G — Clean up

```bash
# host / WSL — unmount anything left, then remove the directory
mount | grep lab03
sudo umount ~/lab03/mountpoint 2>/dev/null
mount | grep lab03           # expect nothing
jobs -p | xargs -r kill 2>/dev/null
rm -rf ~/lab03
```

```bash
# adb shell
rm -rf /data/local/tmp/lab03
```

> **⚠️ Warning**
> Verify with `mount | grep lab03` that nothing remains before deleting the directory. Deleting the
> mount point of a live bind mount leaves a confusing, hard-to-remove entry in the mount table.

---

## Hints

<details>
<summary>Hint 1 — `mkfifo` works but nothing happens when I write to it</summary>

That is correct behaviour. Opening a FIFO for writing blocks until a reader opens it, and vice versa.
You need two terminals. If you want a non-blocking test, use `cat mypipe &` to start the reader in
the background first.
</details>

<details>
<summary>Hint 2 — `sudo unshare --mount` fails or the shell behaves strangely</summary>

On WSL 2 and some hardened distributions, unprivileged user namespaces are restricted. Options: run
with `sudo` (which is what the lab does); on Ubuntu 24.04 and later check
`sysctl kernel.apparmor_restrict_unprivileged_userns` and the AppArmor profile; or do Part E in a
full Linux VM instead of WSL. If `unshare` is missing entirely, install `util-linux`.
</details>

<details>
<summary>Hint 3 — my hand-decoded address is backwards</summary>

You reversed the port as well as the address. The address is byte-reversed (little-endian, as stored
in memory); the port is **not** (network byte order, big-endian, printed as-is). If your address
comes out as `1.0.0.127` you reversed nothing; if your port comes out as 36895 instead of 8080 you
reversed the port. Do the address bytes in reverse and the port digits in order.
</details>

<details>
<summary>Hint 4 — `/proc/net/tcp` on the device shows almost nothing</summary>

Two reasons. Modern Android traffic is largely IPv6, so look in `/proc/net/tcp6`. And a lot of app
traffic is now QUIC over UDP on port 443, which appears in `/proc/net/udp` rather than either TCP
table. Check all four: `tcp`, `tcp6`, `udp`, `udp6`.
</details>

<details>
<summary>Hint 5 — I cannot find the process that owns a socket inode</summary>

You need permission to read that process's `fd/` directory, which means the owning UID or root. From
an unprivileged `adb shell` you can see the socket in `/proc/net/tcp` — including its UID — but not
walk every process's descriptors. Use the UID column to identify the package instead:
`cmd package list packages --uid <n>`.
</details>

<details>
<summary>Hint 6 — `socat` is not on the device</summary>

It usually is not. Use `nc` if present (`toybox nc`), or push a static `socat` or BusyBox build to
`/data/local/tmp`. For most of this lab you do not need it on the device at all — do Parts A, B and E
on your host and use the device only for reading `/proc/net/*` and `/dev/socket/`.
</details>

---

## Solution

### The decoding procedure, as a checklist you can execute cold

```
Given:   0100007F:1F90

1. Split at the colon:        address = 0100007F      port = 1F90
2. Address: split into bytes  01 00 00 7F
3. REVERSE the byte order     7F 00 00 01
4. Hex to decimal, per byte   127 . 0 . 0 . 1
5. Port: do NOT reverse       0x1F90
6. Hex to decimal             1*4096 + 15*256 + 9*16 + 0 = 8080
7. Result                     127.0.0.1:8080
```

For `tcp6`, step 2 becomes: split the 32 hex digits into four 8-digit words, reverse the bytes
**within each word**, then concatenate all sixteen bytes and format as IPv6.

The hex-to-decimal step, without a calculator: each hex digit position is a power of 16, so
`0xABCD = A*4096 + B*256 + C*16 + D`. Memorise `A=10 B=11 C=12 D=13 E=14 F=15` and the four place
values `4096, 256, 16, 1`, and any four-digit hex port is twenty seconds of mental arithmetic.

### Ports worth recognising on sight

| Hex | Decimal | What it usually is |
|---|---|---|
| `0016` | 22 | SSH |
| `0050` | 80 | HTTP |
| `01BB` | 443 | HTTPS |
| `0035` | 53 | DNS |
| `1F90` | 8080 | Common proxy — Burp, mitmproxy |
| `1F91` | 8081 | Second proxy port |
| `15B3` | 5555 | **`adbd` over TCP — wireless debugging** |
| `13AD` | 5037 | The adb server, on the host side |
| `69A2` | 27042 | **`frida-server` default** |
| `69A3` | 27043 | `frida-server` secondary |
| `5D8A` | 23946 | IDA debug server default |

### Why the three IPC mechanisms fail differently

| Mechanism | The failure mode you will find in the wild |
|---|---|
| **FIFO** | Created world-writable, or created in a world-writable directory. Any app can inject messages into the daemon's input stream, and the daemon has no way to tell. Worse: the FIFO can be pre-created by an attacker before the app makes it, so the app writes its data into an attacker-controlled pipe |
| **UNIX socket, pathname** | The mode is right but the daemon never calls `getsockopt(SO_PEERCRED)`, so any process that can reach the path is trusted. Or the mode is `0666` because "the app needs to connect" and no other check was added |
| **UNIX socket, abstract** | There are no permission bits at all, so the *only* controls are `SO_PEERCRED` and SELinux. A vendor daemon that binds an abstract socket and trusts its input is reachable from every app on the device |
| **TCP on localhost** | Any app with the `INTERNET` permission — that is, membership of GID 3003 — can connect to a localhost listener. Apps that run a local HTTP server for a WebView or a debug bridge routinely expose more than they intend |

Every one of those is fixed the same way: **authenticate the peer, do not authenticate the path.**

### The namespace observation, stated precisely

Two processes see different filesystems if and only if `readlink /proc/<pid>/ns/mnt` returns
different values for them. An unprivileged process can read its **own** `ns/mnt` but cannot read
another process's, and it has no baseline to compare its own value against. Therefore:

- A process **can** detect that its mount table looks unusual, if it knows what usual is.
- A process **cannot** detect that another process's mount table differs from its own.
- Therefore every on-device root check that reads `/proc/self/mounts`, `stat()`s a path, or lists a
  directory is answerable by putting the process in its own namespace with the modifications removed.

The escape from that trap is not a better file check. It is hardware-backed attestation, evaluated on
a server, which is where [37 — Root Detection](../../37-RootDetection/README.md) ends up.

---

## Success Criteria

| # | Criterion | Proof |
|---|---|---|
| 1 | You passed a message through a FIFO between two unrelated shells | Transcript from both terminals |
| 2 | You explained why the writer blocked until a reader appeared | One sentence |
| 3 | You identified a FIFO by its `p` type character and stated what decides who may use it | `ls -l` output |
| 4 | You ran a UNIX socket server and read the connecting process's PID and UID from the kernel | `credserver.py` output |
| 5 | You explained why `SO_PEERCRED` cannot be forged and a FIFO has no equivalent | One paragraph |
| 6 | You listed `/dev/socket/` on a device and identified one world-connectable entry | `ls -l` output |
| 7 | You explained what an abstract-namespace socket is and why it has no permissions | One sentence |
| 8 | **You decoded five `/proc/net/tcp` lines completely by hand, before running any script** | Your written working |
| 9 | You correctly identified the frida-server line and the `adbd`-over-TCP line among them | Two answers |
| 10 | You stated the rule about which field is byte-reversed and which is not | One sentence |
| 11 | You traced a socket inode back to the owning PID | The loop's output |
| 12 | Your hand decoding matched `decode-proc-net.py` for every line | Two outputs side by side |
| 13 | You decoded one `tcp6` address, including an IPv4-mapped one | Your working |
| 14 | You created a bind mount and showed the hidden file reappear after unmounting | Three `cat` outputs |
| 15 | You unmounted inside a new namespace and showed the mount still present outside it | Two `grep -c` outputs from two terminals |
| 16 | You proved the two shells had different `ns/mnt` inode numbers | Two `readlink` outputs |
| 17 | You explained why an app cannot detect namespace-based hiding by reading files | One paragraph |
| 18 | You completed the Part D comparison table without looking at the solution | Your table |
| 19 | Every mount you created is gone and both scratch directories are removed | `mount \| grep lab03` empty |

---

## Going Further

1. **Write the descriptor-passing demo.** Extend `credserver.py` to send an open file descriptor with
   `socket.send_fds()` and receive it in a client with `socket.recv_fds()`. Open a file the client's
   UID cannot open, pass the descriptor, and read it from the client. That is a privilege crossing in
   twenty lines, and it is the mechanism behind `ParcelFileDescriptor`.

2. **Decode `/proc/net/udp` and `/proc/net/unix` too.** UDP uses the same address encoding. `unix`
   has a different shape — read `man 5 proc` for the columns, and note which entries are abstract
   (path starting with `@`).

3. **Correlate a Burp capture with `/proc/net/tcp`.** Point a device's traffic at Burp, then dump
   `/proc/net/tcp6` on the device while a request is in flight and find the matching connection. You
   have just cross-validated a proxy capture against the kernel's own record, which is the correct
   response when an app appears to bypass your proxy.

4. **Find every listener on a device and account for each.** `awk '$4=="0A"' /proc/net/tcp
   /proc/net/tcp6`, decode each, map each UID to a package, and write a one-line justification for
   every entry. Anything you cannot justify is a finding.

5. **Explore the other namespace types.** `unshare --net /bin/bash` gives you a shell with its own
   network stack — run `ip addr` inside it and see only a loopback interface. `unshare --uts
   /bin/bash` lets you change the hostname without affecting the parent. Each is a different resource
   made per-process.

6. **Read `system/core/init/` in AOSP** and find where sockets declared in `.rc` files are created,
   including the `socket <name> <type> <mode> <user> <group>` directive. Confirm that the mode you
   read in `ls -l /dev/socket/` matches the `.rc` line. Tracing an observed permission back to the
   policy line that set it is the habit that separates a report from a guess.

---

## Why this matters for Android security

**Decoding `/proc/net/tcp` is a skill you will use on every engagement.** When an app appears to
bypass your proxy, when you need to know whether `frida-server` is reachable, when you must attribute
a connection to a package, or when you are on a device with no tooling at all — the kernel's own
table is always there, always readable, and always true. Being able to read it without a script is
the difference between having a tool and having a capability.

**Classic IPC is where the native Android bugs are.** Binder is well-audited and its security model
is sound. The bugs live in the older machinery that Binder did not replace: vendor daemons on
`/dev/socket`, FIFOs inside app sandboxes, shared memory, and localhost TCP listeners. Every one of
them is triaged with the questions from Part B — who can reach it, and does the receiver check who is
calling? [24 — IPC](../../24-IPC/README.md) turns those questions into an attack methodology.

**Peer credentials are the concept Binder generalises.** `Binder.getCallingUid()` is `SO_PEERCRED`
made mandatory, universal, and impossible to forget. Once you have written a socket server that reads
peer credentials, every Android permission check reads as the same idea with better ergonomics — and
you can immediately see why an app that calls a privileged service without the service checking the
caller is broken.

**Namespaces are why on-device root detection cannot win.** You have now watched two processes read
the same path and get different answers, with neither being deceived. That single observation
explains systemless root, the Magisk DenyList, why file-existence checks fail, and why the industry
moved to Play Integrity and hardware key attestation. When you reach
[62 — Magisk](../../62-Magisk/README.md), there will be nothing left to explain.

**Mount views are also how Android does storage.** `/storage/self/primary` is a per-process bind
mount. Two apps reading `/sdcard` are reading through different views with different visible
contents, enforced by exactly the mechanism in Part E. Scoped storage is a namespace story before it
is an API story.

**Next:** [Lab 04 — CTF: The Hidden Flag](lab-04-ctf-the-hidden-flag.md), which gives you no
instructions at all and expects you to chain permissions, `/proc`, symlinks and namespaces to recover
something deliberately hidden.
