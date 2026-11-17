# 60 — ADB: the Android Debug Bridge protocol and transport

> After this chapter you will be able to open a socket to `adbd`, perform the connect and
> authentication handshake by hand, open and multiplex streams, and install an APK — all without the
> `adb` program. You will be able to say exactly what `adb shell` is, what identity it runs as and
> why, what "always allow from this computer" permanently stores on the device, and when ADB is a
> finding rather than a fact.

**Prerequisites:** [02-Linux-Basics](../02-Linux-Basics/README.md),
[06-Android-Architecture](../06-Android-Architecture/README.md),
[21-App-Sandbox](../21-App-Sandbox/README.md),
[22-SELinux](../22-SELinux/README.md),
[23-Permissions](../23-Permissions/README.md)
**Applies to:** Android 4.2–16 (API 17–36). Everything measured here was measured on
**Android 11 / API 30** (Redmi `M2101K6P`, MIUI 12.5, `user` build, rooted with Magisk/APatch) and on
an **Android 15 / API 35** emulator image. Where the two disagree, both numbers are given.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Deep Internal Working](#3-deep-internal-working)
4. [Source Code Walkthrough (AOSP)](#4-source-code-walkthrough-aosp)
5. [Security Perspective](#5-security-perspective)
6. [Reverse Engineering Perspective](#6-reverse-engineering-perspective)
7. [Dynamic Analysis](#7-dynamic-analysis)
8. [Static Analysis](#8-static-analysis)
9. [Examples](#9-examples)
10. [Common Interview Questions](#10-common-interview-questions)
11. [Common Mistakes](#11-common-mistakes)
12. [Hands-on Labs](#12-hands-on-labs)
13. [Summary](#13-summary)
14. [References](#14-references)

---

## 1. Introduction

### 1.1 What this chapter is, and what it is not

This repository already has a chapter full of `adb` commands.
[77-UsefulCommands](../77-UsefulCommands/README.md) owns that: what to type, what it does, which
subsystem it talks to. **This chapter owns everything underneath the typing.** Where 77 says
"`adb install app.apk` — standard install", this chapter shows you that no such operation exists on
the wire, that it is three separate byte streams carrying three separate command lines and one file,
and that you can drive all three by hand in about eighty lines of Python.

The division matters because the two kinds of knowledge fail differently. Not knowing the command
costs you thirty seconds and a web search. Not knowing the protocol costs you a wrong finding: you
report a device as compromised when it was authorised, or you dismiss an authorised host key as
"just USB debugging" when it is a permanent, transferable credential sitting in a file that survives
factory reboots of the tool but not the device.

> **Definition**
> **ADB** — the Android Debug Bridge. Three cooperating programs and one wire protocol that together
> give a workstation a shell, a file transfer channel, a port forwarder, an installer and a debugger
> attachment point on an Android device, over USB or TCP.

### 1.2 The problem that existed before it

Imagine building a phone operating system in 2007. The device has no keyboard, no terminal, no
removable disk, and a screen the size of a credit card. The team writing the window manager needs to
see a crash log. The team writing the browser needs to push a new build fifty times a day. The
factory needs to flash a serial number. A developer on the other side of the world needs to run a
test suite.

Every one of those is a request to *reach inside a running machine you cannot type on*. On a desktop
you would use `ssh`. But `ssh` needs a network stack that works before the network works, a user
account system that Android does not have in the traditional sense, a shell that exists before the
Java framework has booted, and a password that a factory line cannot manage across a million units.

So Android built its own. And it built it around the one physical connection every phone already
has: the USB cable it charges with.

> **Mental Model**
> ADB is a **service hatch** cut into the side of the device. It is not a door for users; it is a
> hatch for the people who build and repair the thing. Like a real service hatch, three properties
> matter and they are exactly the three that decide every security question in this chapter:
> **who can open it** (authentication), **how big the opening is** (the privilege of the identity
> you get through it), and **whether it can be reached without physical access** (USB versus TCP).

### 1.3 What would break without it

Remove ADB from Android and you remove:

- **Every IDE's run button.** Android Studio does not have a special channel; it shells out to
  `adb install` and `adb shell am start`.
- **Automated testing.** `am instrument`, Espresso, UI Automator, every CI pipeline.
- **Crash diagnosis.** `logcat` is read over ADB. So is `dumpsys`, `bugreport` and every tombstone.
- **Almost all of security testing.** Frida reaches `frida-server` through `adb forward`. Objection
  reaches Frida. MobSF drives a device over ADB. Drozer uses `adb forward`. Burp interception on a
  device with no route to your laptop uses `adb reverse`.
- **The recovery path for a soft-bricked device.**

That last one is why "just remove ADB from production builds" is not the answer Android chose.
Instead it kept the hatch and put a lock on it, and the whole of §3.9 and §5 is about that lock.

### 1.4 The one sentence that decides half your findings

> **Warning**
> `adb shell` is **not an app**. It is a `/system/bin/sh` process forked directly by `adbd`, running
> as UID 2000 (`shell`), in the SELinux domain `shell`, with 183 install-time permissions and
> 16 pre-granted runtime permissions that no third-party application can ever hold. Anything you
> prove from an `adb shell` prompt, you have proved about `shell` — not about an attacker's app.

Every measurement in that sentence was taken on the device described at the top of this chapter, and
§3.12 shows the commands. This is the discipline the rest of the repository keeps referring back to;
this chapter is where the numbers behind it live.

### 1.5 A real-world example to keep in mind

In 2018 a self-propagating cryptominer spread between Android devices by scanning the internet for
TCP port 5555, connecting with the ADB protocol, and — because the devices it found required no
authentication — dropping a payload and executing it. The devices were not phones. They were
set-top boxes, TVs and development boards whose vendors had shipped `adb tcpip` enabled so their own
support staff could reach them.

Nothing in that story is a software vulnerability. There was no memory corruption, no bypass, no
exploit. Every device did exactly what its configuration told it to do. **The vulnerability was the
posture**, and the posture is what §5 teaches you to measure.

---

## 2. High-Level Architecture

### 2.1 Three programs, not one

The word "adb" names three different things, and conflating them is the source of most beginner
confusion.

```mermaid
flowchart TD
    subgraph Host["Your workstation — trust boundary: your user account"]
        C1["adb client<br/>(the binary you type)"]
        C2["adb client<br/>(Android Studio)"]
        C3["adb client<br/>(a test runner)"]
        S["adb SERVER<br/>one per machine, TCP 127.0.0.1:5037<br/>owns every transport"]
        K["~/.android/adbkey<br/>unencrypted RSA private key"]
    end

    subgraph Cable["Physical / network transport"]
        U["USB bulk endpoints<br/>(FunctionFS)"]
        T["TCP :5555<br/>only after adb tcpip"]
    end

    subgraph Device["Android device — trust boundary: adbd's own uid"]
        D["adbd<br/>uid 2000 shell, domain adbd<br/>/apex/com.android.adbd/bin/adbd"]
        SH["/system/bin/sh<br/>forked per shell: stream"]
        CMD["cmd / abb<br/>Binder client into system_server"]
        SY["sync server<br/>SEND/RECV/STAT/LIST"]
        AK["/data/misc/adb/adb_keys<br/>authorised host public keys"]
    end

    C1 --> S
    C2 --> S
    C3 --> S
    K -.->|"signs the auth token"| S
    S -- "ADB wire protocol" --> U
    S -- "ADB wire protocol" --> T
    U --> D
    T --> D
    D --> SH
    D --> CMD
    D --> SY
    AK -.->|"verifies the signature"| D

    style T fill:#f9d0d0
    style AK fill:#f9d0d0
```

Read it from the top. **The `adb` you type is a thin client.** It connects to `127.0.0.1:5037`,
sends a text request, reads a reply, and usually exits. It never touches USB.

**The `adb` server is a background daemon** that the first client starts automatically. It owns the
USB interface, holds one *transport* per device, performs the authentication handshake, and
multiplexes every client's streams onto that transport. This is why `adb kill-server` fixes so much,
why two SDK versions on one machine fight, and why an `adb` client can be a different version from
its server and still mostly work.

**`adbd` is the device-side daemon.** On this API 30 device it is `/apex/com.android.adbd/bin/adbd`,
launched by `init`, running as UID 2000 in SELinux domain `adbd`. Everything you do on the device
happens as a child of that process or as a Binder call made by it.

The two red boxes are the two things that turn "ADB is enabled" into a security problem: the TCP
listener, and the file of permanently authorised keys.

### 2.2 The handshake, message by message

This sequence diagram is not illustrative. It is a transcript of what
[`scripts/adb-mini-client.py`](scripts/adb-mini-client.py) actually sent and received against a
device, with the stream ids the device chose.

```mermaid
sequenceDiagram
    autonumber
    participant H as Host (adb server or our client)
    participant D as adbd on the device

    Note over H,D: Transport is already open — USB bulk pipe, or a TCP socket
    H->>D: socket A_CNXN(version=0x01000001, maxdata=262144,<br/>"host::features=cmd,stat_v2,ls_v2")

    alt ro.adb.secure = 1  (every production device)
        D->>H: socket A_AUTH(TOKEN, 20 random bytes)
        H->>D: socket A_AUTH(SIGNATURE, 256 bytes)<br/>RSA PKCS#1 v1.5 over SHA1-DigestInfo(token)
        alt signature verifies against /data/misc/adb/adb_keys
            D->>H: socket A_CNXN(version, maxdata, "device::ro.product.name=…#59;features=…")
        else signature rejected
            D->>H: socket A_AUTH(TOKEN, a NEW 20-byte token)
            H->>D: socket A_AUTH(RSAPUBLICKEY, 709-byte blob + NUL)
            Note over D: adbd asks system_server over its<br/>seqpacket socket#59; the user sees<br/>"Allow USB debugging?"
            D->>H: socket A_CNXN(...) — only after a human taps Allow
        end
    else ro.adb.secure = 0  (emulators, many embedded builds)
        D->>H: socket A_CNXN(...) immediately — no authentication at all
    end

    H->>D: socket A_OPEN(local-id=1, 0, "shell:id\x00")
    D->>H: socket A_OKAY(remote-id=15, local-id=1)
    D->>H: socket A_WRTE(remote-id=15, local-id=1, "uid=2000(shell)…")
    H->>D: socket A_OKAY(local-id=1, remote-id=15)
    D->>H: socket A_CLSE(remote-id=15, local-id=1)
    H->>D: socket A_CLSE(local-id=1, remote-id=15)
```

Six message types do all of the work. `A_CNXN` establishes the session and exchanges capability
banners. `A_AUTH` is the lock. `A_OPEN` asks for a *service* by name and creates a stream.
`A_OKAY` acknowledges — both as "your stream is open" and, on every subsequent payload, as the whole
of the flow control. `A_WRTE` carries bytes. `A_CLSE` ends a stream in one direction.

Notice what is **not** there. There is no `A_SHELL`, no `A_INSTALL`, no `A_PUSH`. Every capability
ADB has is a *string* passed to `A_OPEN`, and the device decides what to do with it. That single
design decision is why the protocol has barely changed in fifteen years while the feature set has
grown enormously — and it is why enumerating the service strings (§3.6) is the real map of the
attack surface.

### 2.3 The 24-byte header

Everything on the wire is this structure followed by `data_length` bytes of payload.

```
offset  size  field          meaning
------  ----  -------------  ------------------------------------------------
  0      4    command        four ASCII chars read as a little-endian uint32
  4      4    arg0           meaning depends on command
  8      4    arg1           meaning depends on command
 12      4    data_length    payload bytes that follow this header
 16      4    data_check     see below — documented as a CRC32, is not one
 20      4    magic          command XOR 0xffffffff, always
------  ----  -------------  ------------------------------------------------
 24                          payload starts here
```

Here is a real header, captured by the `--verbose` mode of this chapter's client:

```
# host — A_OPEN for the service string "shell:echo hello"
header bytes: 4f50454e 01000000 00000000 11000000 25060000 b0afbab1
              ^command ^arg0     ^arg1     ^len      ^check    ^magic
              "OPEN"   local-id  0         17        0x625     0x4e45504f ^ 0xffffffff
payload:      73 68 65 6c 6c 3a 65 63 68 6f 20 68 65 6c 6c 6f 00
              s  h  e  l  l  :  e  c  h  o     h  e  l  l  o  NUL
```

Read the command field as bytes and it says `4f 50 45 4e` — `OPEN`. Read it as a little-endian
32-bit integer, which is what the code does, and it is `0x4e45504f`. That is the entire reason the
constants in every ADB implementation look like arbitrary hexadecimal.

`magic` is a sanity check with no cryptographic value: it lets a receiver notice instantly that it
has lost byte alignment. If `magic != command ^ 0xffffffff`, the stream is unrecoverable and the
only correct response is to drop the connection.

> **Under the Hood**
> The `data_check` field is documented in AOSP's own `protocol.txt` as a CRC32 of the payload. It
> is not. The implementation sums the payload bytes and truncates to 32 bits, and since protocol
> version `0x01000001` **nobody verifies it at all**. Measured evidence: in every message adbd sent
> to this chapter's client, the field was `0x00000000`, including messages with a non-empty payload.
> Our client computes it honestly and adbd ignores it. Do not use it to detect tampering; there is
> nothing to detect with.

### 2.4 Where the trust boundaries actually are

```mermaid
flowchart LR
    subgraph W["Workstation — anything running as your user"]
        A["adbkey<br/>no passphrase"]
        B["adb server"]
        M["malware running<br/>as your user"]
    end
    subgraph Net["Network — if adb tcpip was ever run"]
        N["anyone who can<br/>route to :5555"]
    end
    subgraph Dev["Device"]
        P(["kernel: USB gadget /<br/>TCP socket"])
        Q["adbd — uid 2000"]
        R["shell — uid 2000<br/>183 install perms"]
        S["system_server — uid 1000"]
    end

    A --> B
    M -. "can read adbkey and<br/>impersonate you forever" .-> A
    B --> P
    N --> P
    P --> Q
    Q --> R
    R -- "Binder" --> S

    style M fill:#f9d0d0
    style N fill:#f9d0d0
    style A fill:#f9d0d0
```

Three things this diagram makes obvious and prose tends to hide.

**The private key is a file, in your home directory, with no passphrase.** Anything that can read
`~/.android/adbkey` can authenticate to every device that has ever trusted you, forever, from any
machine. It is not bound to hardware, not bound to a session, and not revoked by unplugging.

**The device cannot tell an authorised host from a stolen key.** Authentication proves possession of
a private key. It proves nothing about who holds it or where they are.

**Once past `adbd`, you are at UID 2000, and the checks that matter after that are somewhere else
entirely** — in `system_server`, against your calling UID, over Binder. That is why so many `adb`
failures are actually permission or SELinux failures from a completely different subsystem. See
[25-Binder](../25-Binder/README.md) and [22-SELinux](../22-SELinux/README.md).

---

## 3. Deep Internal Working

### 3.1 The client, the server and the daemon

| | adb client | adb server | adbd |
|---|---|---|---|
| **Where** | your workstation | your workstation | the device |
| **Lifetime** | one command | until `adb kill-server` or reboot | boot to shutdown |
| **Listens on** | nothing | TCP `127.0.0.1:5037` | USB gadget, and TCP `:5555` only after `adb tcpip` |
| **Speaks** | the *smart socket* text protocol | smart socket to clients, **wire protocol** to devices | the wire protocol |
| **Holds the key** | no | yes — reads `~/.android/adbkey` | holds the *public* keys in `/data/misc/adb/adb_keys` |
| **Identity** | you | you | uid 2000 `shell`, domain `adbd` |

The two protocols are genuinely different and are frequently confused.

The **smart socket protocol** is what your `adb` binary speaks to the server on port 5037. It is
text: a four-hex-digit length, then a request string, then `OKAY` or `FAIL`. It is documented in
`packages/modules/adb/SERVICES.TXT`.

The **wire protocol** is the 24-byte binary framing of §2.3, spoken between the server and `adbd`.
It is documented in `packages/modules/adb/protocol.txt`.

You can speak the first with `nc`:

```bash
# host — ask the local adb server its version. 000chost:version means
# "12 bytes follow" then the request. The reply is OKAY, a 4-hex length,
# then the payload.
printf '000chost:version' | nc 127.0.0.1 5037
```

`host:` prefixed requests are answered by the server itself; anything else is forwarded to the
current device over the wire protocol. `host:devices-l`, `host:features`, `host:kill` and
`host:track-devices` are the ones worth knowing — `track-devices` is how Android Studio's device
dropdown updates without polling.

> **Pentester's Note**
> Port 5037 is bound to `127.0.0.1`, so it is not remotely reachable by default. But it is
> reachable by **every process running as you**, with no authentication whatsoever. A malicious
> program on your laptop does not need to steal `adbkey`: it can ask the running adb server
> to run commands on every attached device. This is the least-discussed and most immediate risk in
> the entire ADB design, and the mitigation is the boring one — do not run untrusted code on the
> machine that holds your test devices.

### 3.2 Message types in full

| Constant | ASCII | uint32 (LE) | arg0 | arg1 | Payload | Meaning |
|---|---|---|---|---|---|---|
| `A_SYNC` | `SYNC` | `0x434e5953` | online | sequence | — | Legacy internal keepalive; not seen on modern wires |
| `A_CNXN` | `CNXN` | `0x4e584e43` | version | maxdata | banner string + NUL | "Here is who I am and what I can do" |
| `A_AUTH` | `AUTH` | `0x48545541` | type (1/2/3) | 0 | token / signature / public key | The lock — see §3.9 |
| `A_STLS` | `STLS` | `0x534c5453` | version | 0 | — | "This connection must be upgraded to TLS" |
| `A_OPEN` | `OPEN` | `0x4e45504f` | local-id | 0 | service string + NUL | "Open a stream to this service" |
| `A_OKAY` | `OKAY` | `0x59414b4f` | local-id | remote-id | — | "Stream is up" / "I consumed your last write" |
| `A_WRTE` | `WRTE` | `0x45545257` | local-id | remote-id | up to `maxdata` bytes | Stream data |
| `A_CLSE` | `CLSE` | `0x45534c43` | local-id | remote-id | — | "This stream is finished" |

Two conventions catch people out.

**`arg0` is always the sender's own id for the stream, and `arg1` is the peer's.** So the same
stream is `(1, 15)` in messages you send and `(15, 1)` in messages you receive. There is no global
stream identifier; there is a pair, and each side reads the half that is theirs.

**A rejected `A_OPEN` is answered with `A_CLSE` carrying `arg0 = 0`.** Measured: asking for a
service called `nosuchservice:` produced `A_CLSE` with `remote-id=0` and nothing else. There is no
error message and no error code. "Service unavailable", "service unknown" and "service refused
because of a permission check" are indistinguishable on the wire.

### 3.3 Streams, ids and flow control

A single ADB connection carries an arbitrary number of concurrent streams. `adb logcat` running in
one terminal and `adb shell` in another are two streams on one transport, and if you have two
devices, two transports each with their own stream space.

The multiplexing rules are minimal:

1. The side opening a stream picks a **local id**, any non-zero 32-bit value it is not already
   using. The `adb` server counts up from 1.
2. The peer replies `A_OKAY` with its own id in `arg0` and echoes yours in `arg1`.
3. From then on, every message about that stream carries both ids.
4. **Every `A_WRTE` must be acknowledged with an `A_OKAY` before the sender may send another on that
   stream.** That is the entire flow control mechanism: a window of exactly one message.
5. Either side may send `A_CLSE`. The other side replies `A_CLSE` and the id pair becomes reusable.

Rule 4 is the one that bites when you write your own client. Send two `A_WRTE`s back to back and a
strict peer will drop the connection. It also explains an observable performance property: a single
ADB stream cannot pipeline, so `adb push` of a large file is limited by round-trip latency divided
by `maxdata`. That is why `maxdata` was raised from 4 KiB to 256 KiB in protocol version
`0x01000001`, and why `adb push` over TCP to a distant device is so much slower than over USB.

Rule 3 has a subtler consequence that this chapter's installer had to be fixed to handle. adbd is
free to send the `A_CLSE` that finishes stream 1 *after* you have already sent the `A_OPEN` for
stream 2. A client that assumes "the next message answers the request I just made" will read a
stale close as a refusal. The only correct demultiplexing key is `arg1` — your own local id, echoed
back. The comment on `Stream._next_for_me()` in
[`scripts/adb-install-transport.py`](scripts/adb-install-transport.py) records this, because it was
a real bug found by running the code, not a hypothetical.

> **Mental Model**
> An ADB transport is a **tiny TCP stack running inside one connection**. `A_OPEN` is `connect()`,
> the id pair is the four-tuple, `A_WRTE`/`A_OKAY` is send with a one-segment window, and `A_CLSE`
> is `FIN`. If you already understand sockets, you already understand this; the only surprise is
> how small it is.

### 3.4 Service strings — the real attack surface

`A_OPEN`'s payload is a NUL-terminated string. `adbd` parses the part before the first `:` and
dispatches. This table is the map:

| Service string | What it gives you | Notes |
|---|---|---|
| `shell:` | Interactive `/system/bin/sh` with a PTY | Raw byte stream, stdout and stderr merged, no exit code |
| `shell:<command>` | Runs one command, no PTY | What `adb shell ls` sends |
| `shell,v2,raw:<command>` | Same but with the shell-v2 framing | See §3.5 |
| `shell,v2,TERM=xterm,pty:` | Interactive with a PTY, v2 framing | What a modern `adb shell` with no arguments sends |
| `exec:<command>` | Runs a command through `sh` with **binary-safe stdin and stdout** | The transport under `adb install` and `adb exec-out` |
| `abb:<args>` / `abb_exec:<args>` | Runs a `cmd` sub-command with **NUL-delimited arguments and no shell at all** | Android 11+; see §3.6 |
| `sync:` | Switches the stream to the file-transfer sub-protocol | `push`, `pull`, `stat`, `list` |
| `root:` | Restarts adbd as uid 0 — **only if `ro.debuggable=1`** | What `adb root` sends |
| `unroot:` | Restarts adbd as `shell` | What `adb unroot` sends |
| `tcpip:<port>` | Restarts adbd listening on TCP | What `adb tcpip 5555` sends |
| `usb:` | Restarts adbd on USB only | What `adb usb` sends |
| `reboot:<target>` | Reboots, optionally into `bootloader` / `recovery` / `fastboot` | |
| `remount:` | Remounts system partitions read-write | Needs root and often verity disabled |
| `jdwp` | A stream of JDWP-debuggable process ids | How a debugger finds a process |
| `track-jdwp` | Same, but a live feed | |
| `framebuffer:` | A raw screen capture | Predates `screencap` |
| `reverse:forward:<local>;<remote>` | Sets up a **device→host** forward | `adb reverse` |
| `dev:<path>` | Opens a device node directly | Rarely allowed by SELinux |
| `sink:` / `source:` | Bandwidth test endpoints | |

> **Pentester's Note**
> This table is more useful than it looks. If you have found something that speaks the ADB protocol
> — a debug port on an IoT device, an emulator you did not start, a container — the service strings
> are the enumeration surface. `A_OPEN` each one and record whether you get `A_OKAY` or an immediate
> `A_CLSE`. The `--service` flag of [`scripts/adb-mini-client.py`](scripts/adb-mini-client.py) is
> built for exactly that sweep, and Lab 03 walks it.

### 3.5 `shell:` versus `shell,v2:` — measured

This is the clearest example of a capability that is *negotiated in the banner but selected in the
service string*, and getting the distinction wrong makes a hand-written client produce garbage.

Advertising `shell_v2` in your `A_CNXN` banner tells the device you *can* speak the v2 framing. It
does not change anything by itself. The framing is chosen by the service string. Both of these were
run against the same device in the same minute:

```
# service string "shell:echo hi"      — v1
<< A_WRTE  arg0=0x00000013 arg1=0x00000001 len=3
   0000  68 69 0a                    |hi.|

# service string "shell,v2,raw:echo hi" — v2
<< A_WRTE  arg0=0x00000012 arg1=0x00000001 len=8
   0000  01 03 00 00 00 68 69 0a     |.....hi.|
```

The v2 payload is a packet, not a byte stream:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | packet id |
| 1 | 4 | length, little-endian |
| 5 | length | payload |

Packet ids are `0` stdin, `1` stdout, `2` stderr, `3` exit code, `4` close-stdin, `5` window size.
So `01 03 00 00 00 68 69 0a` is "stdout, 3 bytes, `hi\n`", and a second packet with id `3` and a
one-byte payload carries the process exit status.

That exit-code packet is the whole point. **Under `shell:` there is no exit code on the wire at
all** — which is why `adb shell false; echo $?` printed `0` for years, and why every script that
checked the result of an `adb shell` command before Android 8 was silently broken. `adb` works
around it on old devices by appending `; echo $?` to your command and parsing the tail.

| | `shell:` (v1) | `shell,v2:` |
|---|---|---|
| Introduced | Android 1.0 | Android 7.0 / API 24 (`shell_v2` feature) |
| stdout and stderr | merged | separated by packet id |
| Exit code | **not transmitted** | packet id 3 |
| Binary-safe | no — the PTY translates `\n` to `\r\n` | yes, with `raw` |
| Window size changes | no | packet id 5 |

> **Warning**
> The PTY line-ending translation in v1 is why `adb shell cat file.bin > out.bin` corrupts binary
> data on older devices: every `0x0a` becomes `0x0d 0x0a`. Use `adb exec-out cat file.bin`, which
> opens the `exec:` service and is binary-safe. This is a real data-integrity trap in forensic work.

### 3.6 `exec:` and `abb:` — why modern `adb` stopped using a shell

`exec:<command>` hands the command to `/system/bin/sh -c`, which means the device-side shell
performs a round of word splitting and quote removal on whatever you sent. That is a genuine
correctness hazard, and this repository has already been bitten by it once: chapter 09's printed
script sent `su -c "ls -ldZ /data/…"` and the device shell delivered `su -c ls -ldZ /data/…`, so
`su -c` executed only `ls` and the rest became arguments to the *outer* shell.

`abb` — the **Android Binder Bridge**, added in Android 11 — removes the shell from the path
entirely. The service string carries the arguments **delimited by NUL bytes**, and `adbd` passes
them straight to the `cmd` infrastructure over Binder without any shell ever existing.

Measured, against an API 35 device:

```
A_OPEN local-id=1  abb_exec:package \x00 install-create \x00 -r \x00 -S \x00 8538
A_OKAY remote-id=32  (stream up)
reply: Success: created install session [830140676]
```

Two consequences worth internalising:

- **Nothing you can put in an argument will be re-interpreted.** A filename containing a space, a
  semicolon or a `$` survives intact. If you are writing tooling, prefer `abb_exec`.
- **Argv cannot carry a NUL byte**, which is why this chapter's client exposes `--abb "a b c"` and
  builds the delimiters internally rather than accepting the raw service string on the command line.
  That is not a quirk of the script; it is a property of every operating system's `exec` interface.

`abb:` and `abb_exec:` differ the same way `shell,v2:` and `exec:` do: `abb` uses the shell-v2
packet framing (so you get a separate exit code), `abb_exec` is a raw bidirectional byte stream.

### 3.7 The sync sub-protocol — `push` and `pull`

`adb push` and `adb pull` do not use `A_WRTE` payloads directly. They open one stream with the
service string `sync:` and then run a **completely different protocol inside it**, documented in
`packages/modules/adb/SYNC.TXT`.

Every sync message begins with a four-byte ASCII id and a four-byte little-endian length:

| Verb | Direction | Meaning |
|---|---|---|
| `STAT` | host → device | Ask for mode, size and mtime of a path (v1) |
| `STA2` / `LST2` | host → device | The `stat_v2` / `ls_v2` feature versions, with 64-bit sizes and error codes |
| `LIST` | host → device | Enumerate a directory |
| `DENT` | device → host | One directory entry, repeated |
| `SEND` | host → device | Begin a file upload; payload is `<path>,<mode>` |
| `DATA` | host → device | A chunk of file content, up to 64 KiB |
| `DONE` | host → device | End of file; payload length is the mtime |
| `RECV` | host → device | Begin a file download |
| `OKAY` | either | Success |
| `FAIL` | either | Failure; payload is the message |
| `QUIT` | host → device | End the sync session |

Three things follow from this design that matter in practice.

**`adb push` runs as `shell`, so it writes as `shell`.** `/data/local/tmp` is the canonical
destination not because it is special but because it is one of the few places UID 2000 can write
and where SELinux allows it. Pushing to `/data/data/<pkg>/` fails even on a rooted device unless
`adbd` itself is root, because the write happens in `adbd`'s context, not in `su`'s.

**The DATA chunk size is 64 KiB and is independent of `maxdata`.** So a push is doubly framed: 64 KiB
sync chunks packed into up to 256 KiB `A_WRTE` payloads.

**`STAT` v1 cannot express an error.** It returns mode 0 for both "does not exist" and "you are not
allowed to know". `stat_v2` fixed this; the feature is in the banner, and it is one of the reasons
the feature list is worth reading rather than skipping.

#### 3.7.1 A push, message by message

Here is what `adb push local.txt /data/local/tmp/x.txt` actually puts on the wire. The outer layer
is the ADB protocol you already know; the inner layer is the sync protocol.

```
>> A_OPEN(local-id=1, 0, "sync:\x00")
<< A_OKAY(remote-id=7, local-id=1)

   -- from here every A_WRTE payload is sync-protocol framing --

>> A_WRTE  "SEND" <uint32 len> "/data/local/tmp/x.txt,33188"
<< A_OKAY
>> A_WRTE  "DATA" <uint32 len> <up to 64 KiB of file content>
<< A_OKAY
>> A_WRTE  "DATA" <uint32 len> <the next chunk>
<< A_OKAY
   ... repeated ...
>> A_WRTE  "DONE" <uint32 mtime>          <- the length field carries the mtime
<< A_OKAY
<< A_WRTE  "OKAY" <uint32 0>              <- or "FAIL" <len> "<message>"
>> A_OKAY
>> A_WRTE  "QUIT" <uint32 0>
```

Three details that are not obvious from the specification alone:

- **`33188` is `0o100644`** — the file mode, in decimal, appended to the path after a comma. That
  comma is the delimiter, which is why a path containing a comma is a genuine edge case in the sync
  protocol.
- **`DONE`'s length field is not a length.** It carries the modification time. This is the only
  place in either protocol where a length field means something else, and it catches every
  first-time implementer.
- **The 64 KiB chunk size is fixed and independent of `maxdata`.** A push is doubly framed: 64 KiB
  sync chunks packed inside up to 256 KiB `A_WRTE` payloads, each of which still needs its own
  `A_OKAY`.

`RECV` is the mirror: the host sends `RECV` with a path, and the device replies with a series of
`DATA` messages followed by `DONE`. `LIST` replies with a stream of `DENT` records and a final
`DONE`. `STAT` replies with a single fixed-size record — and, in v1, cannot express an error, which
is why `stat_v2` exists.

You can watch this yourself without writing any code:

```bash
# adb shell as root, in one terminal
strace -f -e trace=read,write -p $(pidof adbd) 2>&1 | grep -aoE '(SEND|DATA|DONE|OKAY|FAIL|QUIT|STAT|LIST|RECV)'
```

```bash
# host, in another
adb push /etc/hostname /data/local/tmp/x.txt
adb shell rm /data/local/tmp/x.txt
```

> **Under the Hood**
> On this repository's test device the vendor build **blocks `execve` on `/data/local/tmp`**, so
> pushing a binary there and running it fails even after `chmod +x`. The workaround recorded
> elsewhere in this repo is `adb shell /system/bin/linker64 /data/local/tmp/prog args`, which loads
> the executable through the dynamic linker instead of exec'ing it directly. That is a *transport*
> success and an *execution* failure, and confusing the two wastes an afternoon.

### 3.8 The banner and feature negotiation

The `A_CNXN` payload is `<systemtype>:<serialno>:<banner>`, NUL-terminated. Real, captured:

```
# host — what our client sent
host::features=cmd,stat_v2,ls_v2

# device — what an API 35 adbd replied (line-wrapped here; it is one string)
device::ro.product.name=sdk_gphone16k_x86_64;ro.product.model=sdk_gphone16k_x86_64;
ro.product.device=emu64xa16k;features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,
abb,fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,sendrecv_v2,
sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,
openscreen_mdns,devicetracker_proto_format,devraw,app_info,delayed_ack
```

The `systemtype` is `host`, `device`, `bootloader` or `recovery`. **`adb devices` prints the state
straight from this field** — which is why a device in sideload mode shows as `sideload` and a device
whose `A_CNXN` has not completed shows as `unauthorized` or `offline`.

The feature list is the negotiated capability set for the session, and the effective set is the
**intersection** of the two banners. This is directly observable:

```bash
# host — the device's advertised features (the intersection adb computed)
adb features

# host — everything this adb client could support
adb host-features
```

On this chapter's setup, `adb host-features` listed 22 features and `adb features` listed 12 — the
API 30 device does not implement the other ten.

| Feature | What it changes |
|---|---|
| `shell_v2` | The `shell,v2:` service becomes available: separate streams and an exit code |
| `cmd` | `cmd <service>` exists on the device, so `adb install` can use the session API |
| `abb` / `abb_exec` | Arguments bypass the shell entirely (§3.6) |
| `stat_v2` / `ls_v2` | 64-bit sizes and real errno values in the sync protocol |
| `fixed_push_mkdir` | `adb push` creates missing parent directories correctly |
| `apex` | `adb install --apex` targets APEX modules |
| `remount_shell` | `adb remount` works without a root adbd on some builds |
| `sendrecv_v2*` | Compressed file transfer — brotli, lz4, zstd |
| `openscreen_mdns` | The mDNS implementation used for wireless-debugging discovery |
| `track_app` | A live feed of app process start/stop, used by Studio |
| `delayed_ack` | A larger effective window than the one-message rule of §3.3 |

> **Pentester's Note**
> The banner is a fingerprint you get *before authenticating* on a device that requires no
> authentication, and it leaks `ro.product.name`, `ro.product.model` and `ro.product.device`. On an
> exposed port 5555 that is enough to identify the exact hardware before you do anything else. It
> also means that during a network sweep you can distinguish a real device from a honeypot by
> whether the feature list is internally consistent with the claimed model.

### 3.9 Authentication — the security core

This is the most important section in the chapter.

#### 3.9.1 What the lock is

When `ro.adb.secure` is `1`, `adbd` will not complete `A_CNXN` until the host proves possession of a
private key whose public half is listed on the device. The exchange is three messages:

| `arg0` | Name | Sent by | Payload |
|---|---|---|---|
| 1 | `ADB_AUTH_TOKEN` | device | 20 random bytes |
| 2 | `ADB_AUTH_SIGNATURE` | host | 256 bytes — an RSA-2048 signature |
| 3 | `ADB_AUTH_RSAPUBLICKEY` | host | the public key blob, base64, plus a comment and a NUL |

The signature is RSA PKCS#1 v1.5 over `SHA1-DigestInfo || token`. Note carefully: **the token is not
hashed.** The host side calls OpenSSL's `RSA_sign(NID_sha1, token, 20, ...)`, and `RSA_sign` with a
digest NID expects an already-computed digest — it prepends the ASN.1 DigestInfo prefix and pads.
The token happens to be 20 bytes, the size of a SHA-1 digest, so it is fed straight in. The device
is verifying a signature over a value nobody ever hashed. It works, and it surprises everyone who
reads the code for the first time. The implementation in
[`scripts/adb-mini-client.py`](scripts/adb-mini-client.py) does exactly this and it interoperates.

If the signature verifies, the device replies `A_CNXN` and you are in. If it does not, the device
sends a **new** `A_AUTH(TOKEN)`. That second token is the signal — there is no "auth failed"
message. A host that has more than one key tries each in turn; when it runs out, it sends
`A_AUTH(RSAPUBLICKEY)`, and *that* is the message that makes the "Allow USB debugging?" dialog
appear.

#### 3.9.2 The public key format — measured

The blob in `~/.android/adbkey.pub` and in `/data/misc/adb/adb_keys` is **not** an SPKI, not a PEM,
and not an SSH key. It is a raw C struct from the old `mincrypt` verifier, base64-encoded:

```c
/* the on-disk layout — 524 bytes for RSA-2048 */
struct RSAPublicKey {
    uint32_t len;          /* modulus size in 32-bit words: 64 */
    uint32_t n0inv;        /* -1 / n[0] mod 2^32, a Montgomery constant */
    uint32_t n[len];       /* the modulus,  little-endian words: 256 bytes */
    uint32_t rr[len];      /* R^2 mod n,    little-endian words: 256 bytes */
    int32_t  exponent;     /* 3 or 65537 */
};
```

Verified on the device, printing only structural values and never key material:

```bash
# adb shell as root — sizes and the two key-independent fields only
su -c 'wc -c < /data/misc/adb/adb_keys'                                  # 714
su -c 'cut -d" " -f1 /data/misc/adb/adb_keys | wc -c'                    # 701  (700 + newline)
su -c 'cut -d" " -f1 /data/misc/adb/adb_keys | base64 -d | wc -c'        # 524
su -c 'cut -d" " -f1 /data/misc/adb/adb_keys | base64 -d | od -An -tu4 -N4'   # 64
su -c 'cut -d" " -f1 /data/misc/adb/adb_keys | base64 -d | od -An -tu4 | tail -1'  # 65537
```

`4 + 4 + 256 + 256 + 4 = 524`. The arithmetic closes exactly. `len` is 64 words = 2048 bits, and the
exponent is 65537. Because `len` is the first field and is always 64, **every 2048-bit ADB public
key begins with the base64 characters `QAAA`** — a useful grep anchor when searching a firmware
image or a filesystem dump for authorised keys.

The rest of the line is a free-text comment, conventionally `user@hostname`, written by whichever
`adb` generated the key. It is **not authenticated in any way**. Do not use it to attribute a key.

> **Warning**
> `~/.android/adbkey` is an **unencrypted PKCS#8 private key**. On the machine this chapter was
> written on it is 1,732 bytes beginning `-----BEGIN PRIVATE KEY-----`. There is no passphrase
> prompt because there is no passphrase. Treat that file exactly as you would treat an SSH private
> key with no passphrase — because that is what it is, and it authenticates to every device you have
> ever tapped "Always allow" on.

#### 3.9.3 What "Always allow from this computer" actually persists

Two files, both in `/data/misc/adb/`:

| File | Written by | Contents | Survives |
|---|---|---|---|
| `adb_keys` | `AdbDebuggingManager` in `system_server` | One base64 public key blob plus comment per line | Reboots. Cleared by "Revoke USB debugging authorizations" and by a factory reset |
| `adb_temp_keys.xml` | `AdbDebuggingManager` | `<adbKey key="…" lastConnection="…"/>` per key | Reboots. Used for the automatic-revocation timer |

Measured on the test device:

```bash
# adb shell as root
ls -laZ /data/misc/adb/
# drwxr-s---  2 system shell u:object_r:adb_keys_file:s0     3488 ... .
# -rw-r-----  1 system shell u:object_r:adb_keys_file:s0      714 ... adb_keys
# -rw-------  1 system shell u:object_r:adb_keys_file:s0      854 ... adb_temp_keys.xml
```

and the XML, with the key redacted here:

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<keyStore version="1">
<adbKey key="&lt;REDACTED&gt; user@host" lastConnection="1786359848299" />
</keyStore>
```

`lastConnection` is epoch milliseconds. It exists because Android 11 added **automatic revocation**:
`Settings.Global.ADB_ALLOWED_CONNECTION_TIME` (default 7 days) controls how long an authorised key
survives without being used. That is a genuine improvement in the credential's lifetime, and it is
the reason a device you have not touched in a fortnight asks you to authorise again.

#### 3.9.4 The permission model on the key store itself

The DAC bits say the `shell` group may read `adb_keys`. SELinux says otherwise, and SELinux wins.
Measured:

```
$ adb shell 'cat /data/misc/adb/adb_keys'
cat: /data/misc/adb/adb_keys: Permission denied

$ adb shell 'ls -ld /data/misc/adb'
ls: /data/misc/adb: Permission denied

$ adb shell 'su -c dmesg | grep adb_keys | tail -2'
avc: denied { search } for comm="cat" name="adb" dev="dm-10" ino=240
     scontext=u:r:shell:s0 tcontext=u:object_r:adb_keys_file:s0 tclass=dir permissive=0
avc: denied { getattr } for comm="ls" path="/data/misc/adb" dev="dm-10" ino=240
     scontext=u:r:shell:s0 tcontext=u:object_r:adb_keys_file:s0 tclass=dir permissive=0
```

The directory is created by `init` as `02750 system shell` (see §3.11), so the group read bit is set
and the group *is* `shell`. Yet the shell domain cannot even *search* the directory, because the
SELinux type `adb_keys_file` is not readable by `u:r:shell:s0`. **This is the single cleanest
demonstration in this repository of MAC overriding DAC**, and it is worth running yourself once.

The consequence for testing: **you cannot enumerate a device's authorised keys from `adb shell`.**
You need root. Any tool that claims to list them without root is either wrong or is reading
something else. This chapter's [`scripts/adb-posture.sh`](scripts/adb-posture.sh) reports the denial
honestly rather than printing an empty list.

#### 3.9.5 How the dialog is actually raised

`adbd` cannot draw a dialog; it is a native daemon with no access to the window manager. The path
is:

1. `adbd` receives `A_AUTH(RSAPUBLICKEY)` and cannot verify it against `adb_keys`.
2. `adbd` writes the key to a **seqpacket UNIX socket** created for it by `init`. From the device's
   own `init.usb.rc`:
   ```
   service adbd /system/bin/adbd --root_seclabel=u:r:su:s0
       class core
       socket adbd seqpacket 660 system system
       disabled
       updatable
       seclabel u:r:adbd:s0
   ```
   The `socket adbd seqpacket 660 system system` line is that channel.
3. `AdbDebuggingManager` inside `system_server` reads from it, and starts
   `com.android.systemui`'s `UsbDebuggingActivity` — the dialog you see.
4. If you tap **Allow**, the key is trusted for this session. If you also tick **Always allow from
   this computer**, `AdbDebuggingManager` appends it to `/data/misc/adb/adb_keys` and records it in
   `adb_temp_keys.xml`.
5. `system_server` writes the verdict back down the socket, and `adbd` completes or refuses the
   handshake.

> **Warning**
> Step 3 runs on the device's screen. **If the screen is unlocked, anyone holding the device can
> approve an authorisation.** Since Android 11 the dialog is suppressed while the device is locked,
> which is why "screen lock set" is a genuine, load-bearing mitigation for physical ADB attacks and
> not a checkbox item. Test it: connect a fresh host to a locked device and watch nothing happen.

#### 3.9.6 `A_STLS` and wireless debugging pairing

Android 11 added wireless debugging with a pairing code, and with it a different security model.
When `adbd` is in TLS mode it responds to `A_CNXN` with `A_STLS` instead of `A_AUTH`, and the whole
connection is upgraded to TLS 1.3 with mutual certificate authentication. The pairing step (a six-
digit code shown on the device, entered on the host) runs an SPAKE2 password-authenticated key
exchange to exchange the certificates in the first place.

This is a real improvement over `adb tcpip`:

| | `adb tcpip 5555` | Wireless debugging (`adb pair`) |
|---|---|---|
| Available from | Android 1.x | Android 11 / API 30 |
| Port | fixed 5555 | random, advertised over mDNS |
| Discovery | none; you must know the IP | mDNS `_adb-tls-connect._tcp` |
| Transport security | **none — cleartext** | TLS 1.3, mutual certificates |
| Enrolment | none | SPAKE2 with a one-time 6-digit code |
| Survives reboot | no (unless `persist.adb.tcp.port` is set) | yes, per network |
| Requires the screen | no | yes, to read the code |

[`scripts/adb-mini-client.py`](scripts/adb-mini-client.py) detects `A_STLS`, reports it and stops,
rather than pretending to have connected. Completing that handshake needs the pairing-derived
certificate, not `adbkey`, and no amount of key possession substitutes for it.

### 3.10 adbd's privilege model

#### 3.10.1 The properties that decide everything

| Property | Meaning | Test device (API 30) | Emulator (API 35) |
|---|---|---|---|
| `ro.secure` | `0` means adbd starts as root | `1` | `1` |
| `ro.debuggable` | `1` means `adb root` is honoured | `0` | `1` |
| `ro.build.type` | `user` / `userdebug` / `eng` | `user` | `userdebug` |
| `ro.adb.secure` | `1` means authentication is required | `1` | **`0`** |
| `ro.build.tags` | `release-keys` / `dev-keys` / `test-keys` | `release-keys` | `dev-keys` |

Read those two columns together and the whole model falls out.

On the **`user` build**, `ro.secure=1` so `adbd` drops to UID 2000 at startup; `ro.debuggable=0` so
it will refuse to go back up; `ro.adb.secure=1` so it demands a signature. That is the production
posture, and it is what you should expect on any retail phone.

On the **`userdebug` emulator**, `ro.debuggable=1` so `adb root` works — and `ro.adb.secure=0`, so
**no authentication happens at all**. Our client connected and got a shell without ever being asked
for a key. That is not an emulator quirk to be dismissed; it is the *same* configuration that shipped
on the set-top boxes in §1.5.

Measured refusal on the production device —it is a read-only probe, because adbd declines
without restarting:

```
$ adb root
adbd cannot run as root in production builds
```

and the emulator, where it succeeds:

```
$ adb -s emulator-5554 root
restarting adbd as root
$ adb -s emulator-5554 shell 'ps -A -o PID,USER,LABEL,NAME | grep adbd'
 5129 root         u:r:su:s0                      adbd
```

Look at the SELinux context. A rooted `adbd` does not run in `u:r:adbd:s0` — it transitions to
`u:r:su:s0`, the same domain a Magisk `su` invocation lands in. The domain is supplied by the
`--root_seclabel=u:r:su:s0` argument that `init` passes on the command line, which you can read
straight off the running process:

```
$ adb shell 'cat /proc/$(cut -d" " -f4 /proc/$$/stat)/cmdline' | tr '\0' ' '
/apex/com.android.adbd/bin/adbd --root_seclabel=u:r:su:s0
```

That command deserves a second look, because it also answers a completely different question — see
§3.12.

### 3.11 `adbd` is an APEX module now

On this API 30 device, `/system/bin/adbd` **does not exist**:

```
$ adb shell ls -l /system/bin/adbd
ls: /system/bin/adbd: No such file or directory
$ adb shell "su -c 'readlink /proc/12675/exe'"
/apex/com.android.adbd/bin/adbd
```

`adbd` moved into the `com.android.adbd` APEX in Android 11. The `init` service definition still
names `/system/bin/adbd`, but carries the `updatable` keyword, which tells `init` to resolve the
binary through the APEX mount instead:

```
# /system/etc/init/hw/init.usb.rc, read off the device
mkdir /data/misc/adb 02750 system shell
mkdir /data/adb 0700 root root encryption=Require

service adbd /system/bin/adbd --root_seclabel=u:r:su:s0
    class core
    socket adbd seqpacket 660 system system
    disabled
    updatable
    seclabel u:r:adbd:s0
```

Three facts in eight lines. The `mkdir` explains the exact DAC bits measured in §3.9.4. The
`socket` line is the dialog channel of §3.9.5. And `updatable` means **`adbd` can be patched by a
Mainline update without an OS release** — which is why an ADB fix can reach a device whose vendor
abandoned it, and why "this device is on the 2021 security patch level" does not by itself tell you
`adbd` is unpatched.

`adbd` is started by property trigger, not at boot. From the same device's `init.usb.configfs.rc`:

```
on property:sys.usb.config=adb && property:sys.usb.configfs=1
    start adbd

on property:init.svc.adbd=stopped
    setprop sys.usb.ffs.ready 0
```

`Settings.Global.ADB_ENABLED` is what the developer-options toggle writes; `system_server` observes
it and sets `sys.usb.config`, which fires the trigger. That is the full chain from the switch in the
UI to the process starting.

#### 3.11.1 Capabilities

```
$ adb shell "su -c 'grep -E \"^Cap(Eff|Bnd)\" /proc/12675/status'"
CapEff: 0000000000000000
CapBnd: 00000000000000c0
```

`CapEff` is zero: the running `adbd` holds **no effective Linux capabilities at all**. `CapBnd` is
`0xc0`, bits 6 and 7 — `CAP_SETGID` and `CAP_SETUID`. Those two are retained in the bounding set so
that `adbd` can still change identity for the processes it spawns (this is what makes `run-as`
possible), but it cannot regain any other privilege. If you are reasoning about what a compromised
`adbd` could do, that pair is the ceiling, along with whatever the `adbd` SELinux domain permits.

### 3.12 The `shell` UID — the definitive treatment

The rest of this repository keeps saying "`adb shell` is UID 2000, not an app". Here is the evidence
behind it, and the parts of the claim that are more subtle than the slogan.

#### 3.12.1 Proof that it is not an app

```
$ adb shell 'cat /proc/$(cut -d" " -f4 /proc/$$/stat)/cmdline' | tr '\0' ' '
/apex/com.android.adbd/bin/adbd --root_seclabel=u:r:su:s0

$ adb shell 'ls -l /proc/$$/exe'
lrwxrwxrwx 1 shell shell 0 ... /proc/12022/exe -> /system/bin/sh
```

The **parent of your shell is `adbd`**. Not `zygote`, not `zygote64`. That single fact carries a
lot:

- No `ActivityThread`, no `Application` object, no `Context`, no `onCreate`.
- No ART runtime in the process at all — `sh` is a native binary from toybox.
- No package record, so no `ApplicationInfo`, no `targetSdkVersion`, and therefore **none of the
  behaviour changes that Android gates on `targetSdk`** apply to it. Scoped storage, background
  service limits, non-SDK interface restrictions: a shell process is outside all of them, which is
  precisely why `adb shell` can do things an app of any `targetSdk` cannot.
- No sandbox in the app sense: no per-app SELinux MCS categories, no `/data/data/<pkg>` home.

Compare it with an app process, from [21-App-Sandbox](../21-App-Sandbox/README.md): an app is a
`zygote` fork, gets `u:r:untrusted_app:s0:c<pair>` with unique MCS categories, and lives under
`u0_aNNN`. A shell process is `u:r:shell:s0` with no categories at all.

#### 3.12.2 But `com.android.shell` *is* an app — and this is where it gets subtle

There is a real, installed package with UID 2000:

```
$ adb shell dumpsys package com.android.shell | grep -E 'userId=|codePath=|flags='
    userId=2000
    codePath=/system/priv-app/Shell
    flags=[ SYSTEM HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
    privateFlags=[ ... PRIVILEGED ... ]
```

It shares the UID through `android:sharedUserId="android.uid.shell"`. So UID 2000 is occupied by two
very different kinds of process: the `sh` you get over ADB, and the `com.android.shell` app that
runs `am instrument`, takes bug reports and backs up `dumpstate`.

**This matters because the framework's permission checks are made against the UID, not the process.**
`Binder.getCallingUid()` returns 2000 either way, and `PackageManagerService` resolves 2000 to
`com.android.shell`'s permission set. So the `sh` process — which has no manifest and requested
nothing — inherits every permission the `Shell` app was granted.

Measured on the test device:

```
$ adb shell dumpsys package com.android.shell > /tmp/sp.txt
$ grep -c 'granted=true' <install permissions block>          # 183
$ awk '/runtime permissions:/{f=1} …' | grep -c 'granted=true' # 16
$ grep -c . <requested permissions block>                      # 200
```

**183 install-time permissions granted, 16 runtime permissions pre-granted, out of 200 requested.**
The runtime ones are the striking part:

```
android.permission.CAMERA:                     granted=true, flags=[ SYSTEM_FIXED|GRANTED_BY_DEFAULT ]
android.permission.RECORD_AUDIO:               granted=true, flags=[ SYSTEM_FIXED|GRANTED_BY_DEFAULT ]
android.permission.READ_SMS:                   granted=true, flags=[ SYSTEM_FIXED|GRANTED_BY_DEFAULT|… ]
android.permission.ACCESS_FINE_LOCATION:       granted=true, flags=[ SYSTEM_FIXED|GRANTED_BY_DEFAULT ]
android.permission.ACCESS_BACKGROUND_LOCATION: granted=true, flags=[ SYSTEM_FIXED|GRANTED_BY_DEFAULT|… ]
android.permission.READ_CONTACTS:              granted=true, flags=[ SYSTEM_FIXED|GRANTED_BY_DEFAULT ]
```

`SYSTEM_FIXED` means **the user cannot revoke them**. Camera, microphone, SMS and background
location, permanently granted, to the identity that anyone with an authorised ADB key gets.

Among the install-time set, the ones that shape testing most:

| Permission | What it unlocks |
|---|---|
| `WRITE_SECURE_SETTINGS` | `settings put secure/global …`, including proxies and accessibility services |
| `INSTALL_PACKAGES` | `pm install` without the package installer UI |
| `DUMP` | `dumpsys` against any service |
| `READ_LOGS` | The full logcat, not just your own app's |
| `REAL_GET_TASKS` | The true task list, unlike the neutered `GET_TASKS` |
| `GRANT_RUNTIME_PERMISSIONS` / `REVOKE_RUNTIME_PERMISSIONS` | `pm grant` / `pm revoke` |
| `FORCE_STOP_PACKAGES` | `am force-stop` |
| `SET_DEBUG_APP` | `am set-debug-app -w` |
| `INTERACT_ACROSS_USERS_FULL` | Reaching into work profiles and secondary users |
| `CHANGE_COMPONENT_ENABLED_STATE` | `pm disable` / `pm enable` on other packages |

#### 3.12.3 Where `shell`'s power does *not* come from

There is a persistent myth that `shell`'s privileges come from `platform.xml`. Measured on this
device, the entire `platform.xml` grant to `shell` is a single line:

```xml
<!-- /system/etc/permissions/platform.xml, on the device -->
<assign-permission name="android.permission.INTERNET" uid="shell" />
```

One permission. `assign-permission` exists to give a permission to a **bare UID with no package** —
`media`, `audioserver`, `shell` — because the normal path requires a manifest. Everything else
`shell` can do comes from `com.android.shell`'s own manifest, granted because the package is
`PRIVILEGED` and lives in `/system/priv-app`. See
[23-Permissions](../23-Permissions/README.md) for how `privapp-permissions` allowlists work.

`shell` also holds a set of **supplementary groups**, which is a separate mechanism again:

```
$ adb shell id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),
1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),
3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid)
context=u:r:shell:s0
```

`3003(inet)` is why a shell can open sockets. `1007(log)` is filesystem-level log access.
`3009(readproc)` is why a shell can see other processes in `/proc` at all — without it, `hidepid`
would hide them. `1011(adb)` is the group that exists specifically for this daemon.

#### 3.12.4 The rule that follows

> **Pentester's Note**
> **Never conclude "an attacker can reach this" from the fact that `adb shell` could.** If
> `am start -n com.bank/.AdminActivity` launches a non-exported activity, that tells you `shell`
> holds the relevant privilege — not that a malicious app does. The only acceptable proof is a
> third-party APK running at an ordinary `u0_aNNN` UID doing the same thing. This is the most common
> false positive in junior Android reports, and it is why chapters
> [30-Activities](../30-Activities/README.md) and
> [29-BroadcastReceivers](../29-BroadcastReceivers/README.md) build test apps instead of trusting
> `am`.
>
> The inverse error is just as bad: dismissing a finding because "you needed shell for that". If the
> device is a kiosk with ADB over TCP, `shell` **is** the attacker's identity, and those 183
> permissions are their permissions.

### 3.13 Transports: USB, TCP, mDNS

#### 3.13.1 USB

The device side is **FunctionFS**, a kernel facility that lets a userspace process implement a USB
function. `adbd` opens three files and the kernel exposes a corresponding USB interface to the host:

```
$ adb shell "su -c 'ls -l /proc/\$(pidof adbd)/fd'" | grep usb-ffs
lrwx------ 1 root root 64 ... 13 -> /dev/usb-ffs/adb/ep0
lr-x------ 1 root root 64 ... 14 -> /dev/usb-ffs/adb/ep1
l-wx------ 1 root root 64 ... 15 -> /dev/usb-ffs/adb/ep2
```

`ep0` is the control endpoint, where `adbd` writes the USB descriptors that make the interface
appear with class `0xFF`, subclass `0x42`, protocol `0x01` — the signature every ADB host driver
looks for. `ep1` is bulk OUT (host to device, hence read-only to `adbd`) and `ep2` is bulk IN
(device to host, hence write-only). **Those two file descriptors are the entire USB transport.** The
24-byte headers of §2.3 are written into `ep2` and read from `ep1` with ordinary `read()` and
`write()`.

Two consequences. First, ADB over USB has **no encryption and no integrity protection** — the
authentication proves who you are at connect time and nothing after that. Second, a malicious USB
host sees exactly the interface descriptors above and nothing else; there is no channel binding, no
device attestation, nothing tying the session to the cable.

#### 3.13.2 TCP

`adb tcpip 5555` opens a stream with the service string `tcpip:5555`. `adbd` sets
`service.adb.tcp.port` and restarts itself listening on a TCP socket. The wire protocol is
**byte-for-byte identical**. That is why this chapter's client, which only speaks TCP, teaches you
the USB protocol too.

| Property | Effect |
|---|---|
| `service.adb.tcp.port` | Non-persistent. Cleared on reboot |
| `persist.adb.tcp.port` | **Persistent across reboots.** Seeing this set is much stronger evidence of a deliberate, permanent exposure |

Measured on the test device, and left that way:

```
$ adb shell getprop service.adb.tcp.port      # (empty)
$ adb shell getprop persist.adb.tcp.port      # (empty)
$ adb shell settings get global adb_wifi_enabled
0
```

> **Warning**
> This chapter did **not** run `adb tcpip` on the test device, deliberately. It is a daily-driver
> phone, and turning USB debugging into a network service — on whatever network it happens to join
> next — is not a change to make for a demonstration. Everything in §3.13.2 that needed measuring
> was measured on a disposable emulator instead, and the properties above were re-read afterwards to
> confirm nothing changed.

There is a subtlety the posture script had to be taught. **A listening socket beats a property.**
The emulator listens on 5555 with `service.adb.tcp.port` unset, because the emulator's `adbd` is
started in TCP mode by the emulator rather than by the property trigger:

```
# emulator — the property says nothing, the socket says everything
tcp.service.adb.tcp.port = unset
tcp.5555                 = OPEN
```

Check `/proc/net/tcp` for state `0A` (LISTEN), not just `getprop`.

#### 3.13.3 mDNS

Wireless debugging advertises itself with mDNS service types `_adb._tcp`, `_adb-tls-pairing._tcp`
and `_adb-tls-connect._tcp`. `adb mdns services` lists what the local `adb` server has discovered.
On a corporate or conference network this is a **broadcast advertisement that a debuggable device is
present**, which is worth knowing before you enable it in a client's office.

### 3.14 `adb install` is three streams — the transport half

This is the promise the rest of the repository books against this chapter, so it gets a full
treatment. [09-Android-App-Internals](../09-Android-App-Internals/README.md) owns the package
manager half — what happens *after* commit. This section owns the wire.

There is no install message type. `adb install` is the client running three ordinary commands over
three ordinary streams, tied together by a session id:

```mermaid
sequenceDiagram
    autonumber
    participant H as Host
    participant D as adbd
    participant P as PackageInstallerService (system_server)

    H->>D: socket A_OPEN(1, 0, "exec:cmd package install-create -r -S 8538")
    D->>H: socket A_OKAY(27, 1)
    D->>P: Binder createSession(SessionParams)
    P-->>D: Binder session id 1648417046
    D->>H: socket A_WRTE "Success: created install session [1648417046]"
    Note over P: /data/app/vmdl1648417046.tmp now exists
    D->>H: socket A_CLSE

    H->>D: socket A_OPEN(2, 0, "exec:cmd package install-write -S 8538 1648417046 base -")
    D->>H: socket A_OKAY(28, 2)
    H->>D: socket A_WRTE  8538 bytes of APK  (one chunk#59; maxdata is 262144)
    D->>P: Binder session.openWrite("base").write(...)
    D->>H: socket A_WRTE "Success: streamed 8538 bytes"
    D->>H: socket A_CLSE

    H->>D: socket A_OPEN(3, 0, "exec:cmd package install-commit 1648417046")
    D->>H: socket A_OKAY(29, 3)
    D->>P: Binder session.commit()
    Note over P: verification, signature checks,<br/>dexopt, PackageManagerService
    D->>H: socket A_WRTE "Success"
    D->>H: socket A_CLSE
```

That diagram is a transcript. [`scripts/adb-install-transport.py`](scripts/adb-install-transport.py)
produced it, with no `adb` binary involved, and the package was afterwards visible to
`pm path`. Every number in it — session id, stream ids, byte counts — was read off the wire.

Three things this buys you that "adb install just works" does not:

**The APK is not special.** It travels as `A_WRTE` payloads on a stream opened with a service string,
chunked to the peer's `maxdata`, acknowledged one at a time. There is no difference between shipping
an 8 KiB APK and shipping the output of `ls`. Anything that can carry a shell can carry an install.

**The intermediate state is real and observable.** Between `install-write` and `install-commit`
there is a staging directory that no package query will ever show you. Measured, using the script's
`--no-commit` mode:

```
$ adb shell su 0 ls -l /data/app/vmdl1672322717.tmp
total 16
-rw-r--r-- 1 system system 8538 2026-08-12 13:01 base
```

That file is owned by `system`, sitting on disk, containing a complete APK that is not installed and
that `pm list packages` knows nothing about. If you are doing incident response on a device, an
orphaned `vmdl*.tmp` directory is evidence of an install that was started and never committed.

**A failure tells you which half failed.** If `install-write` returns
`Success: streamed N bytes` and `install-commit` returns `Failure [INSTALL_FAILED_…]`, the transport
did its job perfectly and what you are reading is `PackageManagerService`'s verdict. This repository
has a standing example: on the MIUI test device, `adb install` fails with
`INSTALL_FAILED_USER_RESTRICTED` while `su -c 'pm install'` succeeds with the identical bytes. Same
transport, same file, different caller identity. The transport was never the problem, and neither
`settings put global verifier_verify_adb_installs 0` nor `pm install -i com.android.shell` changes
it — it is an OEM policy keyed on who is asking.

The modern `adb` client uses `abb_exec` rather than `exec` when the device advertises it, which
removes the device-side shell from the path entirely. Both were verified working:

```
A_OPEN local-id=1  abb_exec:package \x00 install-create \x00 -r \x00 -S \x00 8538
reply: Success: created install session [830140676]
```

### 3.15 Port forwarding — how every tool you own actually gets in

Frida, Objection, Burp on a device with no route to your laptop, Chrome DevTools inspecting a
WebView, Drozer, a debugger attaching to an app: **every one of them reaches the device through
`adb forward` or `adb reverse`.** Neither is magic, and neither is a separate protocol.

#### 3.15.1 `adb forward` — a listener on the host

```bash
# host
adb forward tcp:27042 tcp:27042
```

What happens:

1. Your `adb` **client** sends the smart-socket request `forward:tcp:27042;tcp:27042` to the **server**
   on port 5037.
2. The **server** — not the device — opens a listening TCP socket on `127.0.0.1:27042` on your
   workstation.
3. When something connects to that socket, the server opens a **new ADB stream** with the service
   string `tcp:27042` and pipes the two together.

**Everything about a forward lives on the host.** The device sees an ordinary `A_OPEN` for
`tcp:<port>` each time a connection is made, and `adbd` connects to that port on the device's own
loopback interface. There is no persistent device-side state, which is why forwards survive an
`adbd` restart badly and why they vanish when the `adb` server dies.

| Target form | What `adbd` connects to |
|---|---|
| `tcp:<port>` | `127.0.0.1:<port>` on the device |
| `localabstract:<name>` | an abstract-namespace UNIX socket — how `frida-server` is often reached |
| `localfilesystem:<path>` | a filesystem UNIX socket |
| `jdwp:<pid>` | the JDWP channel of a debuggable process (see §3.16) |

```bash
# host — the ones worth memorising
adb forward --list
adb forward tcp:27042 tcp:27042                    # frida-server
adb forward tcp:9229 localabstract:chrome_devtools_remote   # WebView inspection
adb forward --remove-all
```

> **Pentester's Note**
> `adb forward tcp:0 localabstract:chrome_devtools_remote` asks the host to pick a free port and
> prints it. That is the reliable way to script WebView inspection without port collisions — and
> `localabstract:chrome_devtools_remote` is worth remembering on its own, because it is how
> `chrome://inspect` reaches a WebView with `setWebContentsDebuggingEnabled(true)`. See
> [43-WebView](../43-WebView/README.md).

#### 3.15.2 `adb reverse` — a listener on the device

```bash
# host
adb reverse tcp:8080 tcp:8080
```

This is the mirror image, and the asymmetry is where the interesting bit is. The listening socket is
on the **device**, and the connection travels **back up the same ADB transport** to your host.

1. The `adb` server opens a stream with the service string
   `reverse:forward:tcp:8080;tcp:8080`.
2. **`adbd` opens the listening socket**, on the device's loopback.
3. When an app on the device connects to `127.0.0.1:8080`, `adbd` opens a **new stream to the host**
   — `A_OPEN` in the device-to-host direction, which is the only common case where the device is the
   opener — and the host end connects to *your* port 8080.

The practical consequence is enormous and underused:

```bash
# host — intercept traffic with no network route between device and laptop at all
adb reverse tcp:8080 tcp:8080
adb shell settings put global http_proxy 127.0.0.1:8080
# ... test ...
adb shell settings put global http_proxy :0
adb reverse --remove tcp:8080
```

That works on a corporate wifi with client isolation, on a hotel captive portal, on a device with no
wifi at all. **The only physical connection required is the USB cable.**

```bash
# host — always check these before you leave an engagement
adb forward --list
adb reverse --list
```

> **Warning**
> A `reverse` leaves a **listening socket on the device** for as long as it exists, reachable by
> every app on that device. If you forward your Burp instance and then walk away, any app on the
> phone can talk to your proxy. Remove reverses explicitly; they are not cleaned up by
> `adb kill-server`, because the device holds them.

#### 3.15.3 Why this matters for reading a finding

If you have ever wondered how a "local-only" service becomes reachable, this is the mechanism.
A device-side service bound to `127.0.0.1` is not reachable from the network — but it is trivially
reachable by anyone with ADB, through one `adb forward`. So:

- **A localhost-bound service on a device is protected from the network, not from ADB.** If your
  threat model includes a workstation with an authorised key, "we only listen on loopback" is not a
  control.
- **`netstat -tulpn` on the device is worth running on every engagement.** Anything listening on
  loopback is one `adb forward` from your own tooling, and is also reachable by any app on the
  device that can open a socket — which is every app with `INTERNET`. See
  [24-IPC](../24-IPC/README.md).

### 3.16 JDWP — how a debugger finds a process

The Java Debug Wire Protocol is not part of ADB, but ADB is how it is reached, and the interaction
is a small, self-contained example of the transport doing something other than shells and files.

Every process whose `ApplicationInfo` has `FLAG_DEBUGGABLE` — set either by
`android:debuggable="true"` in the app's manifest or globally by `ro.debuggable=1` — registers a
JDWP listener with the runtime. `adbd` exposes two services:

| Service | Behaviour |
|---|---|
| `jdwp` | writes the current list of debuggable process ids and closes |
| `track-jdwp` | writes the list, then writes it again every time it changes, until you close the stream |

```bash
# host — which processes on this device are debuggable right now?
adb jdwp        # this is `track-jdwp`; it does not exit. Ctrl-C when you have the list.
```

Attaching is then an `adb forward` with a `jdwp:` target:

```bash
# host
adb forward tcp:8700 jdwp:$(adb shell pidof -s com.example.target)
jdb -attach localhost:8700
```

Three security consequences worth carrying:

- **`android:debuggable="true"` in a production build is not a hygiene note.** It hands anyone with
  ADB a full Java debugger on your process — read every field, call every method, change every
  value — *and* makes `run-as <pkg>` work for full read/write of the app's private data.
- **`ro.debuggable=1` makes every process on the device debuggable**, which is one of the reasons a
  `userdebug` image in the field is rated so much higher than a `user` one.
- **`track-jdwp` is a live inventory of debuggable processes**, which is a fast triage step: if the
  target appears in it on a stock device, you have found a finding before you have opened the APK.

Apps that care check for this from the other side — `Debug.isDebuggerConnected()`, and
`TracerPid` in `/proc/self/status`. Those checks, and how they are defeated, are
[37-RootDetection](../37-RootDetection/README.md) and
[53-Frida](../53-Frida/README.md).

### 3.17 Version matrix

| Android / API | Change to ADB |
|---|---|
| 4.2.2 / 17 | **RSA authentication introduced** — `ro.adb.secure`, `adb_keys`, the "Allow USB debugging?" dialog |
| 4.4 / 19 | SELinux enforcing; the `adbd` domain gains its modern constraints |
| 5.0 / 21 | `adb backup` matures; `adb reverse` added |
| 7.0 / 24 | `shell_v2` feature: separate stdout/stderr and a real exit code. `cmd` added |
| 8.0 / 26 | `adb install` moves to the PackageInstaller session API by default |
| 9 / 28 | `adb_temp_keys.xml`; per-key connection tracking |
| 10 / 29 | `adb install --incremental` groundwork; `stat_v2` |
| **11 / 30** | **Wireless debugging with `adb pair`, SPAKE2 and TLS (`A_STLS`)**; `abb`/`abb_exec`; `adbd` moves into the `com.android.adbd` **APEX**; automatic authorisation expiry (`ADB_ALLOWED_CONNECTION_TIME`, default 7 days) |
| 12 / 31 | `adb` refuses to connect to a device with a much newer protocol without a matching client |
| 13 / 33 | Tighter restrictions on what `shell` may do to other users' data |
| 14 / 34 | `adb install --bypass-low-target-sdk-block` needed for old APKs |
| 15–16 / 35–36 | `delayed_ack` (a real send window), `devraw`, `app_info`, `openscreen_mdns` in the feature list |

> **Warning**
> Do not read a version table as a substitute for measurement. This repository has already recorded
> one case where a widely repeated version claim was wrong on real hardware. Run
> [`scripts/adb-posture.sh`](scripts/adb-posture.sh) on the device in front of you and quote that.

---

## 4. Source Code Walkthrough (AOSP)

Everything in this chapter is implemented in one AOSP directory:
**`packages/modules/adb/`**. It is one of the most readable modules in the tree — about 30,000 lines
of C++ with two prose specifications in it — and reading it end to end is a genuinely achievable
weekend.

### 4.1 The map

| Path | What lives there |
|---|---|
| `packages/modules/adb/protocol.txt` | **The specification for §2.3 and §3.2.** Prose, in the tree, authoritative |
| `packages/modules/adb/SYNC.TXT` | **The specification for §3.7** — the `sync:` sub-protocol |
| `packages/modules/adb/SERVICES.TXT` | The host smart-socket protocol (port 5037) and the full service-string list |
| `packages/modules/adb/OVERVIEW.TXT` | The client/server/daemon architecture of §2.1 |
| `packages/modules/adb/adb.h` | The `A_*` constants and `struct amessage` |
| `packages/modules/adb/types.h` | `apacket`, and the payload checksum helper |
| `packages/modules/adb/transport.cpp` | Reading and writing packets; the transport registry |
| `packages/modules/adb/transport_usb.cpp` | Framing over the USB bulk endpoints |
| `packages/modules/adb/adb_auth.h` | The `ADB_AUTH_TOKEN` / `SIGNATURE` / `RSAPUBLICKEY` constants |
| `packages/modules/adb/client/auth.cpp` | Host side: loading keys, signing tokens, offering the public key |
| `packages/modules/adb/daemon/auth.cpp` | Device side: verifying signatures, talking to the framework socket |
| `packages/modules/adb/daemon/main.cpp` | `adbd` startup, and the privilege drop of §3.10 |
| `packages/modules/adb/daemon/usb.cpp` | The FunctionFS endpoints of §3.13.1 |
| `packages/modules/adb/services.cpp` | Service-string dispatch — the table in §3.4 |
| `packages/modules/adb/shell_service.cpp` | The `shell:` and `shell,v2:` services, and the v2 packet framing |
| `packages/modules/adb/file_sync_service.cpp` | The device half of `push`/`pull` |
| `packages/modules/adb/client/adb_install.cpp` | **The three-stream install of §3.14** |
| `packages/modules/adb/crypto/rsa_2048_key.cpp` | Key generation, and the `RSAPublicKey` struct encoding |
| `packages/modules/adb/pairing_connection/` | The SPAKE2 wireless-debugging pairing of §3.9.6 |
| `packages/modules/adb/tls/` | The `A_STLS` upgrade |

Two more directories complete the picture:

| Path | What lives there |
|---|---|
| `frameworks/base/services/core/java/com/android/server/adb/AdbDebuggingManager.java` | The framework side: reads adbd's socket, raises the dialog, writes `adb_keys` and `adb_temp_keys.xml`, runs the expiry timer |
| `frameworks/base/packages/SystemUI/src/com/android/systemui/usb/UsbDebuggingActivity.java` | The "Allow USB debugging?" dialog itself |
| `system/core/rootdir/init.usb.rc` | The service definition quoted in §3.11 (vendors ship their own copy) |
| `system/sepolicy/private/adbd.te` | The `adbd` SELinux domain |
| `system/sepolicy/private/shell.te` | The `shell` domain, including the denial measured in §3.9.4 |

### 4.2 Tracing `adb install app.apk` from your keyboard to the disk

This is the complete path. Every step is real; nothing is elided into "and then it installs".

1. **`adb install app.apk`** — your client parses the arguments in
   `client/commandline.cpp`, then calls into `client/adb_install.cpp`.
2. **The client picks a strategy.** If the device's banner contains `cmd`, it uses the streamed
   session install. If it also contains `abb_exec`, arguments go NUL-delimited with no shell. If
   neither, it falls back to the legacy path: push the APK to `/data/local/tmp` and run
   `pm install`. This decision is the reason two devices can behave differently for the same
   command.
3. **The client connects to its own server** on `127.0.0.1:5037` and asks for a transport.
4. **The server opens a stream** with `A_OPEN` and the service string
   `exec:cmd package install-create -r -S <size>` (or the `abb_exec` form).
5. **`adbd` dispatches** in `services.cpp`. For `exec:` it forks `/system/bin/sh -c`; for
   `abb_exec:` it hands the argument vector to the `abb` helper, which is already a Binder client.
6. **`cmd package` runs** — `frameworks/native/cmds/cmd/cmd.cpp` looks up the `package` service via
   `servicemanager` and calls `IBinder::shellCommand()`, passing the argv and the three standard
   file descriptors **over Binder**. Passing FDs is why the command's output arrives back on your
   stream at all. See [25-Binder](../25-Binder/README.md).
7. **`PackageManagerShellCommand.runInstallCreate()`** builds a `SessionParams` and calls
   `PackageInstaller.createSession()`, which returns a session id and creates
   `/data/app/vmdl<id>.tmp`.
8. **Stream 2** carries the APK into `session.openWrite("base", 0, size)`. The bytes go
   `A_WRTE` → `adbd` → the command's stdin → `PackageInstallerSession` → the staging file.
9. **Stream 3 commits.** From here it is chapter 09's territory: signature verification
   ([10-APK-Internals](../10-APK-Internals/README.md)), the install verifier, `dexopt`, the
   `PackageSetting` write, and the `PACKAGE_ADDED` broadcast.
10. **The result string** comes back up stream 3 as `A_WRTE` payloads and your client prints it.

> **Under the Hood**
> Step 6 is where the privilege check happens, and it is not in `adb`. `PackageManagerService`
> checks `Binder.getCallingUid()`, which is 2000, against `INSTALL_PACKAGES`, which
> `com.android.shell` holds. **The transport never checks anything.** `adbd` will happily open a
> stream to a command that will be refused; the refusal arrives as text on that stream. This is the
> same architecture as everywhere else in Android: the transport is dumb, the service enforces.

### 4.3 The authentication path in code

Host side, `client/auth.cpp`:

- `adb_auth_init()` loads every key it can find: `$ADB_VENDOR_KEYS` (a path list),
  `~/.android/adbkey`, and any key the server was told about. Generating one if none exists is
  `crypto/rsa_2048_key.cpp`.
- `adb_auth_get_userkey()` returns the public key in the `RSAPublicKey` struct encoding of §3.9.2.
- `adb_auth_sign()` calls `RSA_sign(NID_sha1, token, token_size, sig, &len, key)` — the call that
  makes the token-is-not-hashed behaviour of §3.9.1 true.

Device side, `daemon/auth.cpp`:

- `adbd_auth_verify()` walks `/data/misc/adb/adb_keys` (and `/adb_keys` on the ramdisk, used by
  recovery), decodes each line and tries `RSA_verify`.
- On failure it calls into `libadbd_auth`, which writes the offered key to the framework socket
  created by the `socket adbd seqpacket 660 system system` line of §3.11.
- `AdbDebuggingManager` on the other side raises the dialog and, on "always allow", appends to
  `adb_keys`.

> **Warning**
> `$ADB_VENDOR_KEYS` is worth knowing about as an attacker and as a defender. It is an environment
> variable naming extra private keys the `adb` client will try. Some OEM and carrier builds ship a
> **vendor key already present in `/adb_keys` on the ramdisk**, so that a factory host can connect
> to any unit without a dialog. If such a key leaks, every device from that vendor with that image
> is authenticated to whoever holds it. Look for `/adb_keys` in a firmware dump; §8 shows how.

---

## 5. Security Perspective

### 5.1 The core claim: an authorised host key is a credential

Everything in this section follows from one sentence. **When a user taps "Always allow from this
computer", the device permanently stores a credential that authenticates a private key file, not a
person, not a computer, and not a session.**

Consider what that credential is like compared with the ones people take seriously:

| | ADB authorised key | SSH `authorized_keys` | A password |
|---|---|---|---|
| Stored where | `/data/misc/adb/adb_keys` on the device | `~/.ssh/authorized_keys` on the server | in the user's head |
| Private half | `~/.android/adbkey`, **no passphrase, ever** | `~/.ssh/id_rsa`, usually with a passphrase | — |
| Transferable | **yes — copy one file** | yes | no |
| Bound to hardware | no | no | no |
| Expires | after `ADB_ALLOWED_CONNECTION_TIME` (7 days idle, Android 11+) | never by default | policy |
| Revocable | Developer options → Revoke USB debugging authorizations | edit the file | change it |
| Visible to the user | a count is not shown anywhere in the UI | `cat` the file | — |
| Grants | uid 2000 with 183 platform permissions | whatever that account has | — |

Two rows do the damage. **No passphrase** means the key is readable by anything running as you.
**No UI showing what is authorised** means a device can accumulate authorisations for years and its
owner has no way to enumerate them — the only control is the all-or-nothing "revoke all".

The attack is not exotic. Malware on a developer's laptop copies one 1,732-byte file. From then on,
that key authenticates to every device the developer has ever authorised, from any machine, with no
prompt.

### 5.2 How attackers abuse ADB

**Exposed TCP, no authentication.** The §1.5 scenario. Scan for 5555, connect, and if
`ro.adb.secure=0` you have a shell with no interaction at all. Self-propagating malware doing
exactly this has been publicly documented since 2018; the affected devices were TV boxes, tablets
and development boards, not phones.

**Exposed TCP, with authentication, and a stolen key.** Same as above but requires the key theft of
§5.1. Much rarer and much more targeted.

**Physical access with an unlocked screen.** Plug in, the dialog appears, tap Allow. Thirty seconds.
This is why the Android 11 change — suppressing the dialog while the device is locked — is a real
control and not cosmetic. Test it rather than assuming your target has it.

**Malicious charging hardware.** A "charger" that is actually a USB host will attempt an ADB
connection. On a device with USB debugging off, nothing happens. On one with it on and an unlocked
screen, the dialog appears — and a hostile kiosk can be built to look like a charging prompt. The
mitigation is the boring one: USB debugging off when not testing, and a screen lock.

**Compromise of the workstation, without touching the key.** Recall §3.1: the adb server listens on
`127.0.0.1:5037` with **no authentication**. Any process running as you can drive every attached
device by talking to it. Stealing `adbkey` is the persistent version; this is the immediate one.

**Leftover `adb reverse` and `adb forward` rules.** A forward set up during testing keeps a port
open on the host or the device. `adb forward --list` and `adb reverse --list` before you leave.

### 5.3 How developers and vendors create the exposure

| Mistake | Where it shows up | How to detect |
|---|---|---|
| Shipping a build with `ro.adb.secure=0` | Embedded devices, TV boxes, kiosks | `adb shell getprop ro.adb.secure`, or just connect with no key |
| Shipping `ro.debuggable=1` in production | Same, plus some carrier builds | `getprop ro.debuggable`; `adb root` succeeding |
| `persist.adb.tcp.port` baked into the image | Devices that come up with 5555 open after every reboot | `getprop persist.adb.tcp.port` |
| A vendor key in `/adb_keys` on the ramdisk | Factory provisioning images | Unpack the boot ramdisk, look for `/adb_keys` |
| An app that enables ADB for the user's convenience | Requires `WRITE_SECURE_SETTINGS`, so priv-apps only | `settings put global adb_enabled 1` in a decompiled priv-app |
| No screen lock on a device with debugging on | Test fleets, demo units | `dumpsys trust`, `locksettings get-disabled` |
| Development `adb tcpip` never turned off | Everywhere | The posture script |

The remediation for a product team, as code, is the boot-time assertion — put it in your device's
`.rc` or your provisioning check:

```bash
#!/usr/bin/env bash
# host — production posture gate. Fail the release if any of these are wrong.
set -euo pipefail
fail=0
check() {  # check <prop> <expected>
  actual="$(adb shell getprop "$1" | tr -d '\r')"
  if [ "$actual" != "$2" ]; then
    echo "FAIL  $1 = '$actual', expected '$2'"; fail=1
  else
    echo "ok    $1 = $actual"
  fi
}
check ro.secure          1
check ro.debuggable      0
check ro.adb.secure      1
check ro.build.type      user
check ro.build.tags      release-keys

for p in service.adb.tcp.port persist.adb.tcp.port; do
  v="$(adb shell getprop "$p" | tr -d '\r')"
  if [ -n "$v" ] && [ "$v" != "-1" ]; then echo "FAIL  $p = $v"; fail=1
  else echo "ok    $p unset"; fi
done

if adb shell 'ls /adb_keys' >/dev/null 2>&1; then
  echo "FAIL  a ramdisk /adb_keys exists — a vendor key is baked into this image"; fail=1
fi

exit $fail
```

### 5.4 Honest severity

This is the part most reports get wrong in both directions.

| Situation | Severity | Why |
|---|---|---|
| USB debugging enabled on **your own test device** | **Not a finding.** Methodology note | It is how you are testing. Record it so the client knows the device was not stock |
| USB debugging enabled on a user's phone, screen locked, `ro.adb.secure=1` | **Informational** | Requires physical access, an unlock, and a deliberate tap |
| USB debugging enabled, **no screen lock**, device left unattended | **Medium** | Thirty seconds of physical access is full `shell` |
| `adb tcpip` left on, on a **trusted lab network** | **Low/Medium** | Depends entirely on who else is on that network |
| `adb tcpip` left on, on a **corporate or public network**, `ro.adb.secure=1` | **Medium/High** | Needs a key, but the surface is remote and permanent until reboot |
| ADB over TCP, `ro.adb.secure=0`, **any** network | **Critical** | Unauthenticated remote shell. No exploit required |
| ADB over TCP on an **unattended kiosk / signage / TV / vehicle head unit** | **Critical** | The device role is the whole finding. Nobody will notice, and nobody will reboot it |
| `ro.debuggable=1` in a shipped product | **High** | Turns the above into a remote **root** shell |
| A vendor key in `/adb_keys` in a public firmware image | **High** | One leak authenticates the entire fleet |

> **Pentester's Note**
> Write the **device role** into the finding. "ADB over TCP is enabled" with no role is unratable
> and a reviewer will discount it. "ADB over TCP is enabled on a customer-facing payment terminal
> that is never rebooted and sits on the store's flat network" is a finding that gets fixed.
> [`scripts/adb-posture.sh`](scripts/adb-posture.sh) prints the evidence and forces you to state
> the role.

### 5.5 The vulnerability classes, with real fixes

**Class 1 — unauthenticated remote debug channel.** Vulnerable configuration:

```
ro.adb.secure=0
persist.adb.tcp.port=5555
```

Why vendors ship it: their support and manufacturing tooling needs to reach devices over the
network, and the pairing flow of §3.9.6 needs a screen and a human. Detection: connect with no key
and see whether `A_CNXN` comes straight back —
`python3 -B scripts/adb-mini-client.py --host <ip> --port 5555 --handshake-only --no-offer-key`
answers it in one command. Fix, as code, in the device's `.rc`:

```
# device init .rc — never persist a TCP debug port in a shipping image
on property:persist.adb.tcp.port=*
    setprop persist.adb.tcp.port ""

on property:ro.build.type=user
    setprop ro.adb.secure 1
```

Honest severity: critical for an unattended networked device, and genuinely not applicable for a
bench unit.

**Class 2 — credential sprawl through "Always allow".** Vulnerable behaviour: a shared test device
accumulating authorisations from every consultant who ever plugged into it, with no UI to review
them. Detection: root, and count `/data/misc/adb/adb_keys`. Fix, operationally: revoke on rotation,
and rely on the Android 11 expiry:

```bash
# adb shell — shorten the automatic revocation window to one day
# (needs WRITE_SECURE_SETTINGS, which shell has)
settings put global adb_allowed_connection_time 86400000
# and to disable time-based revocation entirely (do NOT do this on a shared device)
# settings put global adb_allowed_connection_time 0
```

Honest severity: medium on a shared corporate test fleet, informational on a personal device.

**Class 3 — the workstation is the weak end.** Vulnerable behaviour: `~/.android/adbkey` with no
passphrase, on a machine that browses the internet. Detection is not on the device at all. Fix: full
disk encryption, a dedicated testing machine or VM, and — the one people forget — rotating the key
when a laptop is decommissioned:

```bash
# host — rotate. Then re-authorise each device you still own,
# and revoke on the rest via Developer options.
mv ~/.android/adbkey ~/.android/adbkey.retired
mv ~/.android/adbkey.pub ~/.android/adbkey.pub.retired
adb kill-server && adb devices     # generates a fresh pair
```

Honest severity: not a device finding at all. It belongs in the "testing environment" section of a
report, and it is the one clients most often have no policy for.

### 5.6 OWASP MASVS / MASTG mapping

| Control | How ADB relates |
|---|---|
| **MASVS-RESILIENCE-1** (anti-tampering) | Apps that check `Settings.Global.ADB_ENABLED`, `ro.debuggable` or `ApplicationInfo.FLAG_DEBUGGABLE`; §6 shows how they look and [37-RootDetection](../37-RootDetection/README.md) covers defeating them |
| **MASVS-RESILIENCE-4** (device binding) | An authorised ADB key is *not* device binding; do not treat it as one |
| **MASVS-CODE-2** (debug symbols and code) | `android:debuggable="true"` makes `run-as` work, so ADB turns a hygiene issue into data extraction |
| **MASVS-STORAGE-2** (no sensitive data in logs) | `READ_LOGS`, held by `shell`, is what makes log leakage reachable |
| **MASVS-PLATFORM-1** (IPC) | `am`, `content` and `service` reached over ADB are how you exercise IPC by hand |
| **MASTG-TEST "Basic Security Testing"** | Every setup step in MASTG assumes the transport in this chapter |

### 5.7 The threat model, stated precisely

Most disagreements about ADB severity are actually disagreements about the threat model, held
implicitly. Write it down and the argument resolves itself.

| Attacker position | What they need | What they get | Realistic? |
|---|---|---|---|
| **On the same network, device in TCP mode, `ro.adb.secure=0`** | routing to the port | `shell` immediately; root if `ro.debuggable=1` | Demonstrated repeatedly in the wild on embedded devices |
| **On the same network, TCP mode, `ro.adb.secure=1`** | an authorised private key | the same | Requires prior compromise of an authorised host |
| **Physical access, screen unlocked, USB debugging on** | thirty seconds and a cable | `shell`, and a permanent key if they tick "always allow" | Very realistic for unattended devices |
| **Physical access, screen locked** | to also defeat the lock | nothing, on Android 11+ where the dialog is suppressed while locked | This is why the screen lock is load-bearing |
| **Physical access, USB debugging off** | to enable it, which needs the lock defeated and Developer Options | nothing directly | The default posture is genuinely good |
| **Code execution on the tester's workstation** | nothing more | every attached device, via port 5037, with no prompt; plus `adbkey` for persistence | The least-discussed and most immediate |
| **A malicious USB host (a "charger")** | the device to have debugging on and be unlocked | the consent dialog, dressed up as anything they like | Real, and the reason for the lock-state rule |
| **A stolen `~/.android/adbkey`** | the file | every device that ever trusted that host, from anywhere, until the key expires or is revoked | The persistence mechanism for all of the above |

Two rows are worth arguing about with anyone who dismisses ADB findings.

The **workstation row** is the one nobody models. The `adb` server has no authentication. It is not
a subtle weakness; it is an explicit design decision that the local user is trusted, and it means
"my key is safe" is not the same as "my devices are safe".

The **stolen key row** is the one that turns every other row from an incident into a standing
condition. Nothing about ADB authentication binds a key to a machine, a session, a network or a
piece of hardware.

### 5.8 A remediation catalogue for developers and product teams

Each of these is a real thing teams get wrong, with the fix as configuration rather than as advice.

**Do not ship a debuggable application.**

```xml
<!-- AndroidManifest.xml — WRONG in a release build -->
<application android:debuggable="true" … >
```

Never set it manually at all. The Android Gradle Plugin sets it from the build type, and hard-coding
it overrides that:

```kotlin
// app/build.gradle.kts — let the build type decide, and assert it in CI
android {
    buildTypes {
        release { isDebuggable = false }
        debug   { isDebuggable = true  }
    }
}
```

```bash
# host — CI gate. Fails the build if a release artefact is debuggable.
aapt2 dump badging app-release.apk | grep -q "application-debuggable" \
  && { echo "FAIL: release APK is debuggable"; exit 1; } || echo "ok"
```

**Do not leave WebView debugging on in release.**

```java
// WRONG in release — exposes the WebView to chrome://inspect over adb forward
WebView.setWebContentsDebuggingEnabled(true);
```

```java
// Correct — gate it on your own build config, not on a runtime guess
if (BuildConfig.DEBUG) {
    WebView.setWebContentsDebuggingEnabled(true);
}
```

**Do not ship a device image that permits elevation or skips authentication.** Gate it, as §5.3's
script does, rather than trusting a checklist.

**Do not put a shared provisioning key in the image.** If your factory or support process needs ADB
access, the credential must be per-device or short-lived. A single `/adb_keys` baked into a
publicly downloadable firmware image authenticates the entire fleet to whoever unpacks it.

**Do not treat in-app ADB detection as a security control.**

```java
// A check many hardening libraries make — and what it is actually worth
boolean adb = Settings.Global.getInt(
        ctx.getContentResolver(), Settings.Global.ADB_ENABLED, 0) == 1;
```

`ADB_ENABLED` is 1 on an enormous number of ordinary developer and QA devices. Blocking on it
generates support tickets and stops nobody who is actually attacking you, because anyone with a
debugger can patch the check out — see [37-RootDetection](../37-RootDetection/README.md). Use it as
**telemetry**, not as a gate: record it, correlate it, and make risk decisions server-side where the
attacker cannot reach the code.

**Do give support a channel that is not a debug port.** Every "we left ADB on so support could
reach it" story ends the same way. The fix that survives is an outbound-initiated management channel
with its own authentication and its own audit trail, so that nobody has a reason to revert your
hardening in six months.

### 5.9 Detecting exposure across a fleet

A single device's posture is a point measurement. What a security team needs is drift detection.

```bash
# host — capture every attached device's posture as key=value, one file each
OUT="posture/$(date +%F)"; mkdir -p "$OUT"
adb devices | awk 'NR>1 && $2=="device" {print $1}' | while read -r S; do
  ./scripts/adb-posture.sh -s "$S" --kv > "$OUT/$S.kv"
done

# host — the three fields that actually decide severity
grep -H -E '^(build\.ro\.adb\.secure|build\.ro\.debuggable|tcp\.exposed)=' "$OUT"/*.kv
```

On the network side, an ADB listener is trivially fingerprintable **without connecting**, because a
device answers `A_CNXN` with a plaintext banner:

```
tcp contains "device::ro.product"      # Wireshark display filter
```

and a passive IDS rule can be written against the same string. If you own the network your devices
sit on, alerting on `device::ro.product` crossing it is a cheap, high-signal detection: no
legitimate production traffic contains it.

> **Warning**
> Scanning for port 5555 across a network is a **port scan**, and connecting to what you find is
> **access**. Both need written authorisation naming the ranges. The techniques in this chapter make
> it easy to do accidentally; the fact that a device answers is not consent.

### 5.10 Forensic and incident-response relevance

An examiner cares about ADB for three reasons.

**It is how evidence is acquired**, and every command they run writes to the device's logs, so the
acquisition itself is recorded. Document order of volatility, and capture before you install
anything.

**Authorised keys are an artefact.** `/data/misc/adb/adb_keys` tells you how many hosts were ever
trusted; `adb_temp_keys.xml` tells you when each was last used, in epoch milliseconds. A
`lastConnection` timestamp inside an incident window is a lead. The comment field may name a host —
treat it as unauthenticated hearsay, because it is.

**Orphaned staging directories are an artefact.** `/data/app/vmdl*.tmp` containing a complete `base`
file is an install that was streamed and never committed (§3.14). It carries the APK, which you can
hash and analyse even though the package was never installed.

Also worth capturing: `settings get global adb_enabled`, `getprop service.adb.tcp.port` and
`persist.adb.tcp.port`, and `dumpsys usb`.

---

## 6. Reverse Engineering Perspective

### 6.1 What ADB looks like from inside an app

Apps cannot see the ADB protocol. What they can see, and routinely check, is whether debugging is
*enabled*. In JADX output this is the recognisable shape:

```java
// decompiled from a real-world hardening library
private boolean isDebuggingEnabled(Context context) {
    return Settings.Global.getInt(context.getContentResolver(),
                                  Settings.Global.ADB_ENABLED, 0) == 1;
}

private boolean isDebuggable(Context context) {
    return (context.getApplicationInfo().flags
            & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
}

private boolean isBuildDebuggable() {
    return "1".equals(getSystemProperty("ro.debuggable"));
}
```

In Smali, the first one is unmistakable because `"adb_enabled"` survives obfuscation as a string
constant:

```smali
# the ADB_ENABLED check, in smali
    invoke-virtual {p1}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v0
    const-string v1, "adb_enabled"
    const/4 v2, 0x0
    invoke-static {v0, v1, v2}, Landroid/provider/Settings$Global;->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I
    move-result v0
    const/4 v1, 0x1
    if-ne v0, v1, :cond_0
    const/4 v0, 0x1
    goto :goto_0
    :cond_0
    const/4 v0, 0x0
    :goto_0
    return v0
```

`Settings.Global.ADB_ENABLED` is `public static final String ADB_ENABLED = "adb_enabled"`, and the
compiler inlines the constant. **You cannot obfuscate a string the framework requires you to pass
verbatim**, so the check is always findable:

```bash
# host — find every ADB-awareness check in an APK
grep -rl 'adb_enabled' out/smali*/                       # the settings check
grep -rl 'ro.debuggable' out/smali*/                     # the property check
grep -rn 'FLAG_DEBUGGABLE\|0x2' out/smali*/ | grep -i 'applicationInfo'
```

Obfuscation renames `isDebuggingEnabled` to `a`, moves it into a class called `b`, and possibly
splits it across a lambda. It does not touch `"adb_enabled"`. See
[40-Obfuscation](../40-Obfuscation/README.md).

### 6.2 What ADB looks like in a native library

Native anti-debug code checks the same things through the property API:

```c
/* the C equivalent, as it appears in a stripped .so */
char value[PROP_VALUE_MAX];
__system_property_get("ro.debuggable", value);
if (value[0] == '1') { /* refuse */ }
```

In a disassembler you will see a call to `__system_property_get` (or, in newer code,
`__system_property_find` plus `__system_property_read_callback`) with a string reference. The
strings survive:

```bash
# host — property names an ELF asks about
strings -a lib/arm64-v8a/libfoo.so | grep -E '^ro\.(debuggable|secure|build\.(type|tags))$'
strings -a lib/arm64-v8a/libfoo.so | grep -E 'adb|5555|persist\.sys\.usb'
```

### 6.3 Recognising adbd and the protocol in a firmware image

When you have a firmware dump rather than a running device:

```bash
# host — the daemon and its APEX
find extracted/ -name adbd -o -name 'com.android.adbd*'

# host — the init service definition, which tells you the seclabel and the socket
grep -rn 'service adbd' extracted/system/etc/init/ extracted/vendor/etc/init/

# host — the single highest-value grep in an image: a baked-in vendor key
find extracted/ -name adb_keys
grep -rl 'QAAA' extracted/ 2>/dev/null | head        # every 2048-bit adb key starts QAAA
```

That last grep is §3.9.2 turned into a tool. Because the first field of the `RSAPublicKey` struct is
always `64` for a 2048-bit key, the base64 always begins `QAAA`. A hit inside a ramdisk or a
`/system` image means the vendor pre-authorised a host.

### 6.4 Recognising the protocol in a packet capture

ADB over TCP is cleartext, so a capture on port 5555 is directly readable. Look for:

- The four-byte ASCII command at the start of each 24-byte header: `CNXN`, `OPEN`, `OKAY`, `WRTE`,
  `CLSE`, `AUTH`.
- The `magic` field 20 bytes in, equal to the command XORed with `0xffffffff`. This is the reliable
  discriminator — random traffic will not satisfy it.
- The banner in the first payload, in plain text: `host::features=…` and `device::ro.product.name=…`.

A Wireshark display filter that finds an ADB session with no dissector:

```
tcp contains "host::features=" or tcp contains "device::ro.product"
```

And the shape of the whole thing, if you are writing a parser: read 24 bytes, check the magic, read
`data_length` more, repeat.

Writing that parser is thirty lines and pays for itself the first time you have a capture and no
dissector:

```python
#!/usr/bin/env python3
# host — walk a raw TCP stream (e.g. Wireshark "Follow TCP Stream", saved as raw)
# and print every ADB message in it.
import struct, sys

NAMES = {0x4E584E43: "A_CNXN", 0x48545541: "A_AUTH", 0x4E45504F: "A_OPEN",
         0x59414B4F: "A_OKAY", 0x45545257: "A_WRTE", 0x45534C43: "A_CLSE",
         0x534C5453: "A_STLS", 0x434E5953: "A_SYNC"}

data = open(sys.argv[1], "rb").read()
off = 0
while off + 24 <= len(data):
    cmd, a0, a1, ln, ck, mg = struct.unpack("<6I", data[off:off + 24])
    if NAMES.get(cmd) is None or mg != (cmd ^ 0xFFFFFFFF) & 0xFFFFFFFF:
        off += 1                      # resynchronise: we are not on a header
        continue
    body = data[off + 24:off + 24 + ln]
    print("%-7s arg0=%-6d arg1=%-6d len=%-6d %s"
          % (NAMES[cmd], a0, a1, ln, body[:60]))
    off += 24 + ln
```

The `off += 1` resynchronisation is what makes it usable on a partial capture: because `magic` must
be the command's complement, a false positive is about one in four billion, so byte-walking finds
the real headers reliably.

### 6.5 A complete anti-debug class, as you will meet it

Hardening libraries bundle every ADB-adjacent check into one place. This is the composite shape, in
Java as JADX would render it after renaming:

```java
// decompiled and renamed — the shape, not any specific library
public final class a {
    public static boolean a(Context ctx) {          // "is this device compromised"
        return b(ctx) || c() || d() || e();
    }

    private static boolean b(Context ctx) {         // ADB enabled
        return Settings.Global.getInt(ctx.getContentResolver(), "adb_enabled", 0) == 1;
    }

    private static boolean c() {                    // app itself debuggable
        return (App.get().getApplicationInfo().flags
                & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    private static boolean d() {                    // debugger attached right now
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger();
    }

    private static boolean e() {                    // TracerPid, the native answer
        try (BufferedReader r = new BufferedReader(
                new FileReader("/proc/self/status"))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    return Integer.parseInt(line.split("\\s+")[1].trim()) != 0;
                }
            }
        } catch (Exception ignored) { }
        return false;
    }
}
```

Four checks, four completely different mechanisms, and **four different bypasses** — which is why
"disable root detection" as a single button so often half-works.

| Check | Mechanism | How it is defeated |
|---|---|---|
| `b()` | a `Settings.Global` read over a ContentProvider | hook `Settings.Global.getInt`, or just turn ADB off and use wireless debugging |
| `c()` | a flag in the app's own `ApplicationInfo` | hook `getApplicationInfo`, or do not repackage in the first place |
| `d()` | ART runtime state | hook `Debug.isDebuggerConnected` |
| `e()` | a `/proc` read | hook `open`/`fopen` at the native level, or use an instrumentation method that does not `ptrace` |

The recognisable Smali for `e()`, which is the one that survives Java-level hooking:

```smali
# TracerPid check — the string is the giveaway and cannot be obfuscated away
    new-instance v0, Ljava/io/FileReader;
    const-string v1, "/proc/self/status"
    invoke-direct {v0, v1}, Ljava/io/FileReader;-><init>(Ljava/lang/String;)V
    ...
    const-string v3, "TracerPid:"
    invoke-virtual {v2, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z
    move-result v4
```

### 6.6 What obfuscation does, and does not, do to all this

R8 and commercial obfuscators rename `a`, `b`, `c`, `d`, `e`, inline them into their callers, merge
the class into another, and may move the whole thing into a native library. What they cannot touch:

| Survives obfuscation | Why |
|---|---|
| `"adb_enabled"` | the framework requires this exact string |
| `"/proc/self/status"`, `"TracerPid:"` | filesystem paths and file content, not identifiers |
| `"ro.debuggable"`, `"ro.secure"` | property names passed verbatim to `__system_property_get` |
| The `Landroid/provider/Settings$Global;->getInt` call site | a framework method reference in the DEX |
| `Debug.isDebuggerConnected` | likewise |

So the search that finds every ADB-awareness check in an APK, however obfuscated, is a **string and
call-site** search, never an identifier search:

```bash
# host — works regardless of renaming
grep -rl 'adb_enabled' out/smali*/
grep -rl 'TracerPid' out/smali*/
grep -rl 'ro\.debuggable' out/smali*/
grep -rn 'Settings\$Global;->getInt' out/smali*/ | head
strings -a lib/*/*.so | grep -E '^(ro\.debuggable|ro\.secure|/proc/self/status)$'
```

See [40-Obfuscation](../40-Obfuscation/README.md) for why the string pool is the last thing to be
protected and what a string-encrypting obfuscator changes about this list.

---

## 7. Dynamic Analysis

### 7.1 Speak the protocol yourself — the point of the exercise

Everything in §2 and §3 is verifiable in one command against a device that listens on TCP. An
emulator always does, on `127.0.0.1:5555` for `emulator-5554`.

```bash
# host — the handshake, nothing else
python3 -B scripts/adb-mini-client.py --host 127.0.0.1 --port 5555 --handshake-only
```

Real output, captured:

```
adb-mini-client -> 127.0.0.1:5555
  -> A_CNXN  version=0x01000001 maxdata=262144
  <- A_CNXN  version=0x01000001 maxdata=262144
     systemtype : device
     serial     : (empty)
     banner     : ro.product.name=sdk_gphone16k_x86_64;ro.product.model=…;features=shell_v2,cmd,…

  negotiated features (21):
    abb
    abb_exec
    apex
    …
  our maxdata=262144, theirs=262144, effective=262144
```

Then the same thing with a stream:

```bash
# host — one stream, one command, every message printed
python3 -B scripts/adb-mini-client.py --port 5555 --service "shell:id" -v
```

```
>> A_OPEN  arg0=0x00000001 arg1=0x00000000 len=17
   header bytes: 4f50454e01000000000000001100000025060000b0afbab1
<< A_OKAY  arg0=0x0000000f arg1=0x00000001 len=0
<< A_WRTE  arg0=0x0000000f arg1=0x00000001 len=6
   0000  68 65 6c 6c 6f 0a                                |hello.|
>> A_OKAY  arg0=0x00000001 arg1=0x0000000f len=0
<< A_CLSE  arg0=0x0000000f arg1=0x00000001 len=0
```

> **Pentester's Note**
> Note `cksum=0x00000000` on every message the device sent, including ones with payloads. That is
> the measured proof of the §2.3 claim that the checksum field is dead. You will not find that in
> any tutorial; you find it by looking at the bytes.

### 7.2 Prove that stream identity is decided by `adbd`, not by the protocol

Run the same client, with the same service string, before and after `adb root` on a `userdebug`
target:

```bash
# host — before
python3 -B scripts/adb-mini-client.py --port 5555 --service "shell:id"
#   uid=2000(shell) … context=u:r:shell:s0

adb -s emulator-5554 root
# restarting adbd as root

# host — after. Identical protocol, identical service string.
python3 -B scripts/adb-mini-client.py --port 5555 --service "shell:id"
#   uid=0(root) gid=0(root) … context=u:r:su:s0

adb -s emulator-5554 unroot
```

Both transcripts above are real. Nothing in the protocol changed. **The identity of everything you
do over ADB is the identity of `adbd`**, and that is set at daemon start from `ro.secure`,
`ro.debuggable` and whether `adb root` was honoured.

### 7.3 Sweep the service strings

An `A_OPEN` that is refused returns `A_CLSE` with `arg0 = 0` and no message. That makes a sweep
trivial and is how you enumerate an unknown ADB endpoint:

```bash
# host — which services does this endpoint offer?
for s in "shell:" "shell,v2,raw:id" "exec:id" "sync:" "jdwp" "track-jdwp" \
         "framebuffer:" "reverse:list-forward" "root:" "remount:" "dev:/dev/null" \
         "sink:" "nosuchservice:"; do
  printf '%-24s ' "$s"
  python3 -B scripts/adb-mini-client.py --port 5555 --service "$s" --timeout 2 2>&1 \
    | grep -qE 'A_OKAY' && echo AVAILABLE || echo refused
done
```

> **Warning**
> Do not put `root:`, `tcpip:`, `remount:` or `reboot:` in a sweep you run against a device you care
> about — they take effect immediately. Lab 03 runs this sweep against an emulator for exactly that
> reason, and the list above is safe only because the destructive entries are the last thing you
> should uncomment.

### 7.4 Watch the transport from the device side

With root on the device you can watch `adbd` itself:

```bash
# adb shell as root — what adbd has open right now
ls -l /proc/$(pidof adbd)/fd
```

The interesting entries are the FunctionFS endpoints and one socket per active stream:

```
13 -> /dev/usb-ffs/adb/ep0     control
14 -> /dev/usb-ffs/adb/ep1     bulk OUT — host to device
15 -> /dev/usb-ffs/adb/ep2     bulk IN  — device to host
3  -> socket:[7491855]         …one per stream and per helper
```

```bash
# adb shell as root — trace the reads and writes on the USB endpoints
strace -f -e trace=read,write -p $(pidof adbd) 2>&1 | grep -E 'ep[12]'
```

Every 24-byte header of §2.3 passes through those two file descriptors. Watching a `write(15, …, 24)`
immediately followed by `write(15, …, N)` is the framing, live.

### 7.5 Capture ADB over TCP

On a device that is legitimately in TCP mode (an emulator, or a device you own and have deliberately
switched), the whole session is cleartext:

```bash
# host — capture a whole adb-over-TCP session
sudo tcpdump -i any -s0 -w adb.pcap 'tcp port 5555'
```

Open it in Wireshark and follow the TCP stream: you will see the banner in plain text and every
command you ran. **This is the demonstration to give a client who thinks "it's just USB debugging".**

### 7.6 Frida against `adbd`

`adbd` is a native process running as `shell`, so hooking it needs root:

```javascript
// frida -U -n adbd -l scripts/adbd-trace.js   (device must be rooted)
// Traces every ADB message adbd writes to the transport, decoding the 24-byte header.
'use strict';

const NAMES = {
  0x4e584e43: 'A_CNXN', 0x48545541: 'A_AUTH', 0x4e45504f: 'A_OPEN',
  0x59414b4f: 'A_OKAY', 0x45545257: 'A_WRTE', 0x45534c43: 'A_CLSE',
  0x534c5453: 'A_STLS', 0x434e5953: 'A_SYNC',
};

function decodeHeader(p) {
  const cmd = p.readU32();
  const name = NAMES[cmd];
  if (!name) return null;                       // not a header, just payload
  if ((p.add(20).readU32() >>> 0) !== ((cmd ^ 0xffffffff) >>> 0)) return null;
  return {
    name: name,
    arg0: p.add(4).readU32(),
    arg1: p.add(8).readU32(),
    len:  p.add(12).readU32(),
  };
}

// The USB transport writes with plain write(2) on the bulk-IN endpoint.
Interceptor.attach(Module.getExportByName(null, 'write'), {
  onEnter(args) {
    this.fd  = args[0].toInt32();
    this.buf = args[1];
    this.n   = args[2].toInt32();
  },
  onLeave(retval) {
    if (this.n !== 24) return;                  // headers are exactly 24 bytes
    const h = decodeHeader(this.buf);
    if (!h) return;
    console.log('[adbd fd=' + this.fd + '] ' + h.name +
                ' arg0=' + h.arg0 + ' arg1=' + h.arg1 + ' len=' + h.len);
  },
});

console.log('[+] tracing adbd writes. Run an adb command in another terminal.');
```

Run it and then type `adb shell id` in another terminal; you will see the `A_OKAY`, `A_WRTE` and
`A_CLSE` for that stream appear in order. The full script, with the read side as well, is
[`scripts/adbd-trace.js`](scripts/adbd-trace.js).

> **Warning**
> Attaching Frida to `adbd` on the device you are attached *through* is a good way to lose your
> shell. If the hook throws, `adbd` may die and take your connection with it. Do it on a device you
> can physically reach, and know that `adb kill-server` on the host will not help.

### 7.7 The posture check you should run first, every time

```bash
# host — read-only; never enables TCP, never writes to /data/misc/adb
./scripts/adb-posture.sh -s <serial> --root
```

Real output from the test device is quoted throughout §3; the sections are Device, Build stance,
adbd itself, Network exposure, Authorised keys, Shell identity, and a severity call with its
reasoning shown so you can disagree with it.

---

## 8. Static Analysis

### 8.1 In an APK

There is nothing about the ADB *protocol* in an APK. What there is:

| What to look for | Command |
|---|---|
| `android:debuggable="true"` | `aapt2 dump xmltree app.apk --file AndroidManifest.xml \| grep -i debuggable` |
| ADB-awareness checks | `grep -rl 'adb_enabled' out/smali*/` |
| Build-property checks | `grep -rl 'ro.debuggable\|ro.secure\|ro.build.tags' out/smali*/` |
| Native property checks | `strings -a lib/*/*.so \| grep -E '^ro\.(debuggable\|secure)$'` |
| An app that toggles ADB | `grep -rn 'WRITE_SECURE_SETTINGS' out/` then look for `Settings.Global.putInt` |
| `allowBackup` (a different extraction route with the same cable) | `aapt2 dump badging app.apk \| grep -i backup` |

> **Warning**
> `android:debuggable="true"` in the manifest is a **serious** finding, not a hygiene note, and the
> reason is entirely about ADB: it makes `run-as <pkg>` work, which gives anyone with a shell full
> read/write access to that app's private data with no root. See
> [21-App-Sandbox](../21-App-Sandbox/README.md) and
> [33-Storage](../33-Storage/README.md).

### 8.2 In a firmware image or a device tree

This is where ADB static analysis actually lives.

```bash
# host — the init service definition: seclabel, root_seclabel, socket, updatable
grep -rn --include='*.rc' -A6 'service adbd' extracted/

# host — property defaults baked into the image
grep -rhn -E '^(ro\.secure|ro\.debuggable|ro\.adb\.secure|persist\.adb\.tcp\.port|ro\.build\.type)=' \
  extracted/system/build.prop extracted/vendor/build.prop \
  extracted/system/etc/prop.default extracted/default.prop 2>/dev/null

# host — a pre-authorised vendor key (see 6.3)
find extracted/ -name adb_keys -o -name 'adb_keys*'

# host — the SELinux domain, if the policy sources shipped
grep -rn 'adbd' extracted/system/etc/selinux/*.cil | head -40
```

The four properties in that second command are the whole posture, and finding
`persist.adb.tcp.port=5555` in a `build.prop` is a finding you can write before you ever power the
device on.

### 8.3 In an AOSP or vendor tree

```bash
# host, in an AOSP checkout — the specifications
sed -n '1,80p' packages/modules/adb/protocol.txt
sed -n '1,60p' packages/modules/adb/SYNC.TXT
grep -n 'A_CNXN\|A_AUTH\|A_OPEN\|A_OKAY\|A_WRTE\|A_CLSE\|A_STLS' packages/modules/adb/adb.h

# host — the service-string dispatch table of section 3.4
grep -n 'strncmp\|ConsumePrefix\|StartsWith' packages/modules/adb/services.cpp | head -40

# host — where the privilege drop happens
grep -n 'setuid\|setgid\|capset\|should_drop_privileges' packages/modules/adb/daemon/main.cpp
```

### 8.4 On a live device, without root

Most of the posture is readable as `shell`:

```bash
# adb shell — everything that does not need root
getprop ro.secure; getprop ro.debuggable; getprop ro.adb.secure
getprop ro.build.type; getprop ro.build.tags
getprop service.adb.tcp.port; getprop persist.adb.tcp.port
settings get global adb_enabled
settings get global adb_wifi_enabled
settings get global adb_allowed_connection_time
ps -A -o PID,USER,LABEL,NAME | grep adbd
cat /proc/net/tcp | awk '$4=="0A"'          # listening sockets
```

The one thing that is **not** readable without root is the authorised-key store, for the SELinux
reason in §3.9.4. Any checklist that tells you to `cat /data/misc/adb/adb_keys` from `adb shell` has
never been run on a real device.

### 8.5 A firmware ADB triage, as a script

For an embedded device, an OEM image or a leaked build, the whole ADB posture can be read before you
power anything on. This is the pass to run first.

```bash
#!/usr/bin/env bash
# host — ADB posture triage of an UNPACKED firmware image.
#   usage: fw-adb-triage.sh /path/to/extracted
# Read-only. Reports what an attacker would find; makes no judgements about
# device role, because the image cannot tell you that.
set -uo pipefail
ROOT="${1:?usage: fw-adb-triage.sh <extracted-image-root>}"

echo "== 1. properties that decide the posture =="
grep -rhn -E '^(ro\.secure|ro\.debuggable|ro\.adb\.secure|ro\.build\.type|ro\.build\.tags|persist\.adb\.tcp\.port|service\.adb\.tcp\.port)=' \
  "$ROOT"/system/build.prop "$ROOT"/vendor/build.prop \
  "$ROOT"/system/etc/prop.default "$ROOT"/default.prop \
  "$ROOT"/product/build.prop 2>/dev/null | sort -u

echo
echo "== 2. the adbd service definition =="
grep -rn --include='*.rc' -A8 'service adbd' "$ROOT" 2>/dev/null | head -30

echo
echo "== 3. property triggers that start it =="
grep -rn --include='*.rc' -B2 'start adbd' "$ROOT" 2>/dev/null | head -20

echo
echo "== 4. PRE-AUTHORISED VENDOR KEYS -- the highest-value finding here =="
found=0
while IFS= read -r f; do
  found=1
  echo "  FOUND: ${f#$ROOT}"
  echo "         $(grep -c '' "$f" 2>/dev/null) key(s)"
  # Structural check only. Do NOT print the key.
  awk '{ printf "         entry %d: base64 field %d chars\n", NR, length($1) }' "$f" 2>/dev/null
done < <(find "$ROOT" -name adb_keys 2>/dev/null)
[ "$found" = 0 ] && echo "  none found"

echo
echo "== 5. anything that looks like an adb public key anywhere in the image =="
# every 2048-bit adb public key's base64 begins QAAA (len = 64 words)
grep -rlE 'QAAA[A-Za-z0-9+/]{600,}' "$ROOT" 2>/dev/null | head

echo
echo "== 6. where does adbd live =="
find "$ROOT" -name adbd -o -name 'com.android.adbd*' 2>/dev/null | head

echo
echo "== 7. SELinux, if policy sources shipped =="
grep -rl 'adb_keys_file' "$ROOT"/system/etc/selinux/ 2>/dev/null | head
```

The section that matters most is 4 and 5. A `/adb_keys` inside a ramdisk, or a `QAAA…` blob anywhere
in a publicly downloadable image, means the vendor pre-authorised a host — and every unit that
shipped with that image is authenticated to whoever holds the matching private key.

Section 1 is next: `ro.adb.secure=0` or `persist.adb.tcp.port=5555` in a `build.prop` is a finding
you can write before the device is ever plugged in.

---

## 9. Examples

All five run against a device or emulator you own. Numbers shown are real output from this
chapter's setup.

### 9.1 Simple — talk to the adb server with `nc`

The host-side smart-socket protocol is text and needs no tooling at all.

```bash
# host — 000c is hex for 12, the length of "host:version"
printf '000chost:version' | nc 127.0.0.1 5037; echo
# OKAY00040029          -> OKAY, then 4 hex digits of length, then 0x0029 = 41

printf '000ehost:devices-l' | nc 127.0.0.1 5037; echo
# OKAY0055<serial>  device product:sweetin model:M2101K6P device:sweetin transport_id:1
```

You have just done what `adb devices` does. The `adb` binary is a formatter around this.

### 9.2 Intermediate — the handshake by hand, with the header decoded

```bash
# host
python3 -B scripts/adb-mini-client.py --port 5555 --service "shell:getprop ro.build.version.sdk" -v
```

Work through the first two headers in the output by hand:

```
>> 434e584e 01000001 00040000 21000000 030c0000 bcb1a7b1
   ^CNXN    ^version ^maxdata ^len=33  ^cksum   ^magic

   0x4e584e43 ^ 0xffffffff = 0xb1a7b1bc  -> matches the magic field. Framing is good.
   maxdata 0x00040000 = 262144 = 256 KiB -> protocol version 0x01000001 behaviour.
   payload: "host::features=cmd,stat_v2,ls_v2" + one NUL = 33 bytes. Matches len.
```

Then the reply, where the interesting field is the one that is zero:

```
<< 434e584e 01000001 00040000 8b010000 00000000 bcb1a7b1
                              ^len=395 ^cksum = 0 for a 395-byte payload
```

395 bytes of banner and a zero checksum. That is §2.3's claim, measured.

### 9.3 Advanced — install an APK with no `adb` binary

Build a throwaway APK out of tree — no code, no components, just enough to be a valid package:

```bash
# host — build in a scratch directory, never inside the repository
SDK="$HOME/AppData/Local/Android/Sdk"; BT="$SDK/build-tools/35.0.1"
mkdir -p /tmp/probe && cd /tmp/probe
cat > AndroidManifest.xml <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.pentest.ch60.probe" android:versionCode="1" android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30" />
    <application android:label="ch60probe" android:hasCode="false" />
</manifest>
XML
"$BT/aapt2" link -o unsigned.apk --manifest AndroidManifest.xml \
    -I "$SDK/platforms/android-35/android.jar" --min-sdk-version 21 --target-sdk-version 30
"$BT/zipalign" -p -f 4 unsigned.apk aligned.apk
"$BT/apksigner" sign --ks ~/.android/debug.keystore --ks-pass pass:android \
    --ks-key-alias androiddebugkey --key-pass pass:android --out probe.apk aligned.apk
```

Then install it over the raw protocol:

```bash
# host
python3 -B scripts/adb-install-transport.py --port 5555 --apk /tmp/probe/probe.apk
```

Real output:

```
connected. maxdata=262144
transport: exec (via sh)
APK: /tmp/probe/probe.apk  (8538 bytes)

STREAM 1 -- install-create
  A_OPEN local-id=1  exec:cmd package install-create -r -S 8538
  A_OKAY remote-id=27  (stream up)
  reply: Success: created install session [1648417046]
  a staging directory now exists at /data/app/vmdl1648417046.tmp

STREAM 2 -- install-write  (the APK travels as A_WRTE payloads)
  A_OPEN local-id=2  exec:cmd package install-write -S 8538 1648417046 base -
  A_OKAY remote-id=28  (stream up)
  A_WRTE APK body: 8538 bytes in 1 chunk(s) of at most 262144
  reply: Success: streamed 8538 bytes

STREAM 3 -- install-commit
  A_OPEN local-id=3  exec:cmd package install-commit 1648417046
  A_OKAY remote-id=29  (stream up)
  reply: Success

RESULT: installed
```

and the confirmation from the ordinary tool:

```
$ adb shell pm path com.pentest.ch60.probe
package:/data/app/~~S9bIfk1_eRlR3wTFRHfxuQ==/com.pentest.ch60.probe-SeEoxofAyx7QsByADoLwpg==/base.apk
```

### 9.4 Real application — a posture assessment you can put in a report

```bash
# host
./scripts/adb-posture.sh -s 84f7a024 --root
```

The parts that decide the finding, verbatim from the test device:

```
build.ro.secure                    1
build.ro.debuggable                0
build.type                         user
build.ro.adb.secure                1
adb.root.permitted                 no (ro.debuggable=0) — adb root will be refused
adb.authentication                 REQUIRED — adbd sends A_AUTH and verifies a signature
adbd.user                          shell
adbd.selinux                       u:r:adbd:s0
adbd.origin                        APEX (com.android.adbd) — updatable without an OS update
settings.adb_enabled               1
settings.adb_wifi_enabled          0
tcp.service.adb.tcp.port           unset (USB only until next adb tcpip)
tcp.persist.adb.tcp.port           unset
tcp.5555                           not listening
tcp.exposed                        no
keys.readable.as.shell             NO — and that is correct
keys.count                         1
keys.bytes                         714
keys.field.widths                  700
keys.temp.entries                  1
keys.temp.lastConnection           1786359848299  (Mon Aug 10 16:34:08 IST 2026)
shell.runtime.perms.granted        16
```

The write-up that follows from it is two sentences: *USB debugging is enabled with one authorised
host key, last used on 10 August. The device requires authentication, is not reachable over the
network, and `adbd` cannot be elevated to root, so this is an informational observation about the
test device's configuration rather than a finding.* That is what an honest ADB section looks like.

Contrast the same script against the emulator:

```
build.ro.debuggable=1
build.ro.adb.secure=0
adb.authentication=NOT REQUIRED — any host that can reach adbd is trusted immediately
tcp.5555=OPEN — the classic adb-over-TCP port is listening
tcp.exposed=YES
```

Two fields. Same tool. Completely different severity.

### 9.5 Enterprise — fleet posture as a diffable artefact

```bash
#!/usr/bin/env bash
# host — capture the ADB posture of every attached device as key=value,
# one file per serial, so a fleet can be diffed between audits.
set -euo pipefail
OUT="posture/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

adb devices | awk 'NR>1 && $2=="device" {print $1}' | while read -r S; do
  echo "== $S"
  ./scripts/adb-posture.sh -s "$S" --kv > "$OUT/$S.kv"
done

# the two lines that decide whether anyone needs to be woken up
grep -H -E '^(tcp\.exposed|build\.ro\.adb\.secure|build\.ro\.debuggable)=' "$OUT"/*.kv

# diff against the previous run
PREV="$(ls -d posture/* | tail -2 | head -1)"
for f in "$OUT"/*.kv; do
  b="$(basename "$f")"
  [ -f "$PREV/$b" ] && diff -u "$PREV/$b" "$f" || echo "NEW DEVICE: $b"
done
```

The point is the last block. A fleet posture number is nearly useless; a **fleet posture diff** is
actionable, because it tells you which device changed and when.

---

## 10. Common Interview Questions

### Beginner

**Q: What is `adbd`?**
The Android Debug Bridge daemon: a native process on the device, started by `init`, that implements
the device end of the ADB protocol. On a production build it runs as UID 2000 (`shell`) in the
SELinux domain `adbd`. Since Android 11 it ships inside the `com.android.adbd` APEX, so it can be
updated without an OS release.

**Q: Why does my device say "unauthorized"?**
Because `adbd` sent `A_AUTH(TOKEN)`, your host signed it with `~/.android/adbkey`, and the signature
did not verify against any key in `/data/misc/adb/adb_keys`. The host then offered its public key,
which raises the "Allow USB debugging?" dialog on the device. Until someone taps Allow, the `A_CNXN`
never completes and `adb devices` shows `unauthorized`. Common causes: a new host, a fresh key, a
factory reset, "Revoke USB debugging authorizations", or the Android 11+ seven-day idle expiry.

**Q: What is the difference between `adb root` and `su`?**
`adb root` asks the *daemon* to restart as UID 0, which only works when `ro.debuggable=1` — that is,
on `userdebug` and `eng` builds. Every process you then spawn inherits root. `su` is a separate
binary installed by a rooting solution such as Magisk; you run it *inside* a normal `adb shell`, and
only the command you pass it becomes root. On a retail phone, `adb root` prints
`adbd cannot run as root in production builds` and `su` is your only route. They also land in
different SELinux domains: a rooted `adbd` is `u:r:su:s0`, and an ordinary shell stays `u:r:shell:s0`
until it execs `su`.

**Q: Why can `adb` read files my app cannot?**
Because `adb shell` is not your app. It runs as UID 2000, and UID 2000 is shared with
`com.android.shell`, a privileged system package holding 183 install-time permissions — `DUMP`,
`READ_LOGS`, `WRITE_SECURE_SETTINGS`, `INSTALL_PACKAGES`, `REAL_GET_TASKS` — plus 16 pre-granted,
non-revocable runtime permissions. It also has no `targetSdkVersion`, so none of the storage or
background restrictions that apply to apps apply to it. Anything you can do from `adb shell` is
evidence about `shell`, not about an app.

**Q: Is `adb` over wifi safe?**
It depends which one you mean. `adb tcpip 5555` is **cleartext, on a fixed port, with no transport
security** — only the connect-time RSA check, which does not protect the session at all. Wireless
debugging (`adb pair`, Android 11+) is TLS 1.3 with mutual certificates enrolled through a SPAKE2
exchange keyed on a six-digit code, on a random mDNS-advertised port. The first is a real exposure
on any network you do not control; the second is genuinely reasonable. Neither should be left on
when you are not using it.

### Intermediate

**Q: Walk me through the 24-byte ADB header.**
Six little-endian `uint32`s: `command`, `arg0`, `arg1`, `data_length`, `data_check`, `magic`. The
command is four ASCII bytes read as an integer, so `OPEN` is `0x4e45504f`. `magic` is the command
XORed with `0xffffffff` and exists only to detect lost framing. `data_check` is documented as a
CRC32, is implemented as a byte sum, and has not been verified by anything since protocol version
`0x01000001` — on a real device it arrives as zero.

**Q: How does ADB multiplex several shells over one cable?**
Each stream is identified by a pair of ids. The opener picks a local id and sends
`A_OPEN(local, 0, "service\x00")`; the peer replies `A_OKAY(its own id, your id)`. Every subsequent
message carries both. Flow control is a one-message window: each `A_WRTE` must be acknowledged with
an `A_OKAY` before another is sent on that stream. `A_CLSE` from either side ends it. There is no
global stream identifier — you demultiplex on `arg1`, your own id echoed back.

**Q: What does "Always allow from this computer" store, and where?**
The host's RSA public key, in the `mincrypt` `RSAPublicKey` struct encoding, base64 with a free-text
comment, appended to `/data/misc/adb/adb_keys` by `AdbDebuggingManager` in `system_server`. The key
is also recorded in `/data/misc/adb/adb_temp_keys.xml` with a `lastConnection` timestamp used for
the automatic seven-day expiry added in Android 11. Both files are mode `0640 system:shell`, but
SELinux denies the `shell` domain even a directory search, so you need root to read them.

**Q: What exactly happens when you run `adb install`?**
Three streams. `exec:cmd package install-create -S <size>` returns a session id and creates
`/data/app/vmdl<id>.tmp`; `exec:cmd package install-write -S <size> <id> base -` carries the APK as
ordinary `A_WRTE` payloads into that staging file; `exec:cmd package install-commit <id>` triggers
verification and installation. On a device advertising `abb_exec`, the same three commands go with
NUL-delimited arguments and no device-side shell. There is no install message type in the protocol.

**Q: Why is `adb exec-out cat file.bin > f.bin` correct where `adb shell cat` is not?**
`shell:` allocates a PTY, and the PTY line discipline translates `\n` into `\r\n`, corrupting binary
data. `exec:` is a raw bidirectional byte stream with no PTY. On devices with the `shell_v2` feature
the modern client can also use `shell,v2,raw:`, which separates stdout from stderr and gives you an
exit code.

### Senior

**Q: An IoT device has an open port that answers on 5555. Take me from there to a verdict.**
Connect and read the `A_CNXN` reply without authenticating. If it comes straight back, the device
has `ro.adb.secure=0` and you have an unauthenticated shell — critical, with no further work. If it
answers `A_AUTH(TOKEN)`, authentication is on; sign with your key, and expect a second token, at
which point stop rather than offering your public key on a device you do not own. Either way, record
the banner: it carries `ro.product.name`, `ro.product.model` and `ro.product.device`, plus the
feature list, which fingerprints the platform. If you get a shell, the next questions are `id` (is
`adbd` root?), `getprop ro.debuggable`, and whether `persist.adb.tcp.port` is set, which tells you
whether the exposure survives a reboot. Severity is decided by the device's role, not by the
protocol.

**Q: Why is an authorised ADB key more dangerous than an SSH key, and less dangerous?**
More: it has no passphrase, ever; there is no UI to enumerate what has been authorised; and it
grants an identity with 183 platform permissions rather than one user account. Less: it is
constrained to one device's `shell` UID rather than a general-purpose account, SELinux still applies
on top of it, and since Android 11 it expires after seven idle days. The honest comparison is "an
SSH key with no passphrase, to an account with sudo-adjacent capability, that nobody can list".

**Q: You run `am start -n com.bank/.AdminActivity` from `adb shell` and a non-exported activity
launches. Is that a finding?**
Not from that evidence. `shell` holds privileges no app has, and the export check in
`ActivityStarter` is made against the calling UID, which is 2000. The only proof is a third-party
APK at an ordinary `u0_aNNN` UID doing the same thing. But the inverse mistake matters too: if the
device in scope is a kiosk with ADB over TCP, `shell` *is* the attacker's identity and the same
result is a genuine finding. State the assumed attacker position.

**Q: Design a way to give factory technicians ADB access to a shipped fleet without shipping a
universal key.**
Expect: no shared secret in the image; per-device or per-batch enrolment; a key that the device can
verify but that an attacker with one device cannot reuse on another. A workable answer is a
short-lived certificate signed by a manufacturing CA, checked by `adbd` against a public key in the
image, with the device's serial in the subject — so a leaked credential is scoped to one unit and
expires. Discuss the Android 11 pairing flow as prior art (SPAKE2 with a one-time code) and why it
does not fit a headless factory line, then discuss revocation, clock trust, and what happens when
the manufacturing CA key leaks.

### Staff Engineer

**Q: The ADB checksum field is dead. Would you add integrity protection, and where?**
The right answer starts by noting that a checksum was never a security control and that adding one
would not be either — an attacker on the wire can recompute it. If the threat is a passive or active
attacker on the transport, the answer is the `A_STLS` path: TLS with mutual authentication, which
Android already built for wireless debugging. The interesting design question is why USB does not
use it, and the answer is that the USB transport is assumed to be a physical trust boundary — which
is exactly the assumption a malicious charger violates. A good candidate proposal is to extend the
TLS upgrade to USB, and the objection to argue against is boot-time and recovery-mode complexity,
where the crypto stack may not exist yet.

**Q: You own an Android-based product. Write the ADB policy.**
Expect: `ro.adb.secure=1` and `ro.debuggable=0` gated in CI, not by convention; no
`persist.adb.tcp.port` in any shipping image; no `/adb_keys` in the ramdisk; ADB off by default and
requiring physical presence plus an unlocked screen to enable; a documented, time-limited support
mode with per-device credentials; a fleet posture check that runs continuously and alerts on drift;
and — the part people forget — a plan for the devices already in the field with the wrong
configuration, because a policy that only covers new builds fixes nothing.

**Q: Where does the ADB trust model actually break in a large organisation?**
On the workstations, not the devices. The device end is a reasonable design; the host end is an
unencrypted key file plus an unauthenticated localhost port on every developer's laptop. The
mitigations are organisational: dedicated test hardware, full-disk encryption, key rotation on
offboarding, and not letting the machine that holds the test fleet's keys be the machine that reads
email.

### Principal Engineer

**Q: ADB's design has barely changed since 2008. Is that a success or a failure?**
Argue both. Success: a six-message protocol with a string-named service dispatch has absorbed
fifteen years of feature growth — sync, install sessions, `abb`, TLS, mDNS discovery — without a
breaking change, because the extension point is a string rather than an opcode. Every ADB client
ever written still connects. Failure: the security model is bolted on rather than designed in.
Authentication was added five years late, in 4.2.2; the checksum field is a vestige that documents
an intent nobody implemented; the transport is unauthenticated after connect; and the credential is
an unencrypted file with no lifecycle. A protocol whose *framing* aged well and whose *trust model*
aged badly is the honest summary, and the lesson for your own designs is that extensibility and
security age on different timescales.

**Q: If you could change one thing about ADB, what and why?**
A strong answer picks something with a clear threat model and an argued cost. For example: bind the
host credential to hardware — require the private key to live in a TPM, Secure Enclave or platform
keystore so that stealing a file is not enough. That directly kills the §5.1 attack, costs
compatibility with every existing client, and needs a fallback for CI machines and Linux boxes with
no such hardware, which is where the discussion gets interesting. A weaker answer proposes
"encrypt the connection" without noticing that Android already did, for wireless, and that the
remaining gap is USB where the assumed threat model is different.

---

## 11. Common Mistakes

### 11.1 Developer and vendor mistakes

- **Shipping `ro.adb.secure=0`** because the factory tooling needed it and nobody removed it.
- **Baking `persist.adb.tcp.port=5555` into an image.** The non-persistent form at least dies at
  reboot; this one never does.
- **Shipping a vendor key in `/adb_keys`.** One leak authenticates the fleet.
- **Assuming ADB is off because Developer Options is hidden.** `settings put global adb_enabled 1`
  works from any process with `WRITE_SECURE_SETTINGS`, and hiding a menu is not a control.
- **Shipping `android:debuggable="true"`.** It converts anyone with `shell` into someone with full
  read/write access to your app's private data, via `run-as`.
- **Treating "ADB requires a dialog" as sufficient.** It is, only if the device has a screen lock and
  the platform suppresses the dialog while locked. Both must be true.
- **Detecting ADB in-app and treating it as an attack.** `Settings.Global.ADB_ENABLED` is 1 on a
  huge fraction of developer devices and QA fleets; blocking on it generates support tickets and
  stops nobody serious. See [37-RootDetection](../37-RootDetection/README.md).

### 11.2 Pentester mistakes

- **Reporting `shell`-only access as an app vulnerability.** The most common junior error in this
  entire field. §3.12.4.
- **Reporting "USB debugging is enabled" as a finding with no device role.** Unratable.
- **Running `adb tcpip` on a client network, or on your own daily driver.** You have just created
  the exposure you were hired to find.
- **Sweeping service strings including `root:`, `tcpip:`, `remount:` or `reboot:`.** These take
  effect immediately. §7.3.
- **Offering your public key to a device you do not own.** `A_AUTH(RSAPUBLICKEY)` raises a dialog on
  someone else's screen and leaves your key in their `adb_keys` if they tap Allow. Use
  `--no-offer-key`.
- **Copying `~/.android/adbkey` into a repository, a ticket or a screenshot.** It is a credential.
- **Concluding "the device has no authorised keys" from an empty `adb shell cat`.** You were denied
  by SELinux; the file may be full. §3.9.4.
- **Trusting a version table over the device.** Run the posture script.
- **Using `adb shell cat file.bin > out.bin` for binary data.** PTY translation corrupts it. §3.5.
- **Forgetting `adb forward --list` and `adb reverse --list`** and leaving ports open after the
  engagement.

### 11.3 Reverse engineer mistakes

- **Assuming the `data_check` field means anything.** It is zero on the wire.
- **Assuming stream ids are stable or meaningful.** They are per-connection and chosen by whoever
  opens the stream; the same command produced remote ids 11, 15, 18 and 27 in one session here.
- **Assuming the next message answers the request you just sent.** adbd interleaves streams;
  demultiplex on `arg1`. This was a real bug in this chapter's own installer.
- **Confusing the smart-socket protocol with the wire protocol.** `host:version` on port 5037 is not
  an ADB message and has no 24-byte header.
- **Assuming the banner is trustworthy.** It is a string the peer chose. A honeypot can claim to be
  a Pixel.
- **Assuming `shell_v2` in the banner changes the framing.** It enables the `shell,v2:` *service*;
  the service string selects the framing. §3.5.
- **Looking for `/system/bin/adbd` on a modern device.** It is in the APEX. §3.11.

---

## 12. Hands-on Labs

Full material is in [`labs/`](labs/). Work them in order; each assumes the previous one.

| Lab | Objective | Difficulty |
|---|---|---|
| [Lab 01 — Read the wire](labs/lab-01-read-the-wire.md) | Decode real 24-byte headers by hand, verify the magic and the dead checksum, and map a whole `adb shell` session to its message sequence | Beginner |
| [Lab 02 — Speak the protocol](labs/lab-02-speak-the-protocol.md) | Connect to `adbd` with no `adb` client, complete `A_CNXN`, handle `A_AUTH`, open a stream and run a command. **This is the lab that makes the protocol real** | Intermediate |
| [Lab 03 — Posture and exposure](labs/lab-03-posture-and-exposure.md) | Enumerate a device's ADB posture, sweep its service strings, measure the `shell` identity, and write a defensible severity for three different device roles | Intermediate |
| [Lab 04 — CTF: The unattended terminal](labs/lab-04-ctf-unattended-terminal.md) | Five flags on a simulated exposed device: fingerprint it from the banner alone, get a shell, find the install that was never committed, identify the authorised host, and explain the misconfiguration that made it all possible | Advanced |

**Assignment.** After Lab 02, delete the client you were given and write your own from the
specification in `packages/modules/adb/protocol.txt`. It is about 150 lines. Nothing in this chapter
will stick the way that will.

---

## 13. Summary

### Key points

- ADB is **three programs**: a thin client, a host server on `127.0.0.1:5037` that owns every
  transport and holds your key, and `adbd` on the device.
- Two protocols, routinely confused: the **text smart-socket protocol** to the server, and the
  **binary wire protocol** to `adbd`.
- The wire protocol is a **24-byte header** — command, arg0, arg1, data_length, data_check, magic —
  and six message types: `A_CNXN`, `A_AUTH`, `A_OPEN`, `A_OKAY`, `A_WRTE`, `A_CLSE`.
- `data_check` is documented as a CRC32, implemented as a byte sum, and **verified by nobody**. It
  arrives as zero.
- Capability is a **string passed to `A_OPEN`**, not an opcode. `shell:`, `exec:`, `abb_exec:`,
  `sync:`, `root:`, `tcpip:`. That string list is the attack surface.
- Streams are an **id pair**; flow control is a **one-message window**; demultiplex on `arg1`.
- Authentication is `A_AUTH` with an **RSA-2048 PKCS#1 v1.5 signature over a 20-byte token that
  nobody hashed**. The public key is a 524-byte `mincrypt` struct, base64, always starting `QAAA`.
- "Always allow from this computer" writes a **permanent, transferable credential** to
  `/data/misc/adb/adb_keys`, backed by an **unencrypted private key** in `~/.android/adbkey`.
- `shell` cannot read that file — **DAC says yes, SELinux says no**, measured with an AVC.
- `adbd` drops to UID 2000 when `ro.secure=1`, and only `ro.debuggable=1` lets `adb root` put it
  back to UID 0 in domain `u:r:su:s0`. Since Android 11 it ships in the **`com.android.adbd` APEX**.
- **`adb shell` is not an app.** Its parent is `adbd`, it has no `targetSdk`, and it inherits
  `com.android.shell`'s 183 install permissions and 16 non-revocable runtime permissions.
- **`adb install` is three streams** driving the PackageInstaller session API, with an observable
  staging directory in between.
- `adb tcpip` is **cleartext on a fixed port**. Wireless debugging (`adb pair`) is TLS 1.3 with
  SPAKE2 enrolment. They are not the same thing.
- "ADB enabled" is not a finding. "ADB enabled, over TCP, unauthenticated, on an unattended device"
  is a critical one. **The device's role is the finding.**

### Mind map

```mermaid
mindmap
  root((ADB<br/>protocol and transport))
    Three programs
      client — thin, exits
      server — 127.0.0.1:5037, owns transports, holds the key
      adbd — uid 2000, domain adbd, APEX since 11
    Wire protocol
      24-byte header
        command arg0 arg1
        data_length data_check magic
        magic = cmd XOR 0xffffffff
        checksum is dead
      Messages
        A_CNXN banner and features
        A_AUTH token / signature / pubkey
        A_STLS TLS upgrade
        A_OPEN A_OKAY A_WRTE A_CLSE
      Streams
        id pair, arg1 is yours
        one-message window
        A_CLSE arg0=0 means refused
    Services
      shell: and shell,v2:
      exec: — binary safe
      abb_exec: — NUL args, no shell
      sync: — SEND RECV STAT DONE
      root: unroot: tcpip: usb:
      reverse: framebuffer: jdwp
    Authentication
      ro.adb.secure gates it
      RSA-2048 PKCS#1 v1.5
      token is NOT hashed
      pubkey = 524-byte mincrypt struct
      adb_keys — permanent credential
      adb_temp_keys.xml — 7-day expiry
      SELinux denies shell the read
      dialog via adbd seqpacket socket
    Privilege
      ro.secure drops to shell
      ro.debuggable allows adb root
      rooted adbd is u:r:su:s0
      CapEff 0, CapBnd SETUID SETGID
      shell is NOT an app
        parent is adbd, not zygote
        no targetSdk
        183 install perms
        16 SYSTEM_FIXED runtime perms
    Transports
      USB FunctionFS ep0 ep1 ep2
      TCP 5555 — cleartext
      mDNS + TLS pairing (11+)
    Install
      install-create
      install-write — A_WRTE payloads
      install-commit
      vmdl<session>.tmp staging
    Severity
      test device — not a finding
      TCP + no auth — critical
      role decides everything
```

### Condensed cheat sheet

| Need | Answer |
|---|---|
| Header size | 24 bytes, six LE uint32 |
| Magic | `command ^ 0xffffffff` |
| Checksum | byte sum; unverified; arrives as 0 |
| Protocol version | `0x01000001` — maxdata 256 KiB |
| Stream id you read | `arg1` |
| Flow control window | one `A_WRTE` |
| Refused service | `A_CLSE` with `arg0 = 0` |
| Auth signature | RSA-2048 PKCS#1 v1.5 over `SHA1-DigestInfo \|\| token`, token unhashed |
| Public key size | 524 bytes; base64 starts `QAAA` |
| Authorised keys | `/data/misc/adb/adb_keys`, root only |
| Expiry setting | `settings get global adb_allowed_connection_time` |
| adbd binary | `/apex/com.android.adbd/bin/adbd` (Android 11+) |
| adbd domain | `u:r:adbd:s0`; rooted → `u:r:su:s0` |
| `adb root` allowed | only when `ro.debuggable=1` |
| Shell uid | 2000, shared with `com.android.shell` |
| Binary-safe read | `adb exec-out cat f` — never `adb shell cat` |
| Install | three streams: create / write / commit |
| Staging dir | `/data/app/vmdl<session>.tmp` |
| TCP exposure props | `service.adb.tcp.port`, `persist.adb.tcp.port` |
| Listening check | `/proc/net/tcp`, state `0A` |

### Quick revision

- What are the six fields of the ADB header, and which one is meaningless?
- Which field do you use to work out which stream a message belongs to, and why not the other one?
- What does `A_CLSE` with `arg0 = 0` mean?
- What is signed during authentication, and what is *not* done to it first?
- Where does "Always allow from this computer" write, and why can't `adb shell` read it?
- Name the two properties that decide whether `adb root` can work, and what each does.
- Why is `adb shell` not an app, and how would you prove it in one command?
- How many install permissions does UID 2000 hold on a stock device, and where do they come from?
- What three service strings does `adb install` open, in order?
- What is left on disk between `install-write` and `install-commit`?
- What is the difference between `adb tcpip` and wireless debugging, in one sentence?
- When is "ADB is enabled" a finding, and when is it not?

---

## 14. References

### AOSP source

- `packages/modules/adb/protocol.txt` — the wire protocol specification. Read this first.
- `packages/modules/adb/SYNC.TXT` — the `sync:` file-transfer sub-protocol.
- `packages/modules/adb/SERVICES.TXT` — the host smart-socket protocol and the service-string list.
- `packages/modules/adb/OVERVIEW.TXT` — the client/server/daemon architecture.
- `packages/modules/adb/adb.h` — the `A_*` constants and `struct amessage`.
- `packages/modules/adb/transport.cpp` — packet reading and writing.
- `packages/modules/adb/daemon/main.cpp` — `adbd` startup and the privilege drop.
- `packages/modules/adb/daemon/auth.cpp`, `client/auth.cpp` — both halves of `A_AUTH`.
- `packages/modules/adb/services.cpp` — service-string dispatch.
- `packages/modules/adb/shell_service.cpp` — `shell:` and the v2 packet framing.
- `packages/modules/adb/client/adb_install.cpp` — the three-stream install.
- `packages/modules/adb/pairing_connection/` — SPAKE2 wireless-debugging pairing.
- `frameworks/base/services/core/java/com/android/server/adb/AdbDebuggingManager.java` — the
  authorisation dialog, `adb_keys` and the expiry timer.
- `system/sepolicy/private/adbd.te`, `system/sepolicy/private/shell.te` — the two SELinux domains.
- Android Code Search — https://cs.android.com/

### Official documentation

- Android Debug Bridge — https://developer.android.com/tools/adb
- Wireless debugging (Android 11+) — https://developer.android.com/tools/adb#wireless-android11-command-line
- ADB security and authorisation — https://source.android.com/docs/core/architecture/kernel/adb
- APEX / Mainline modules — https://source.android.com/docs/core/ota/modular-system
- Android permissions reference — https://developer.android.com/reference/android/Manifest.permission

### Standards

- RFC 8017 — PKCS #1 v2.2, the RSA signature padding used by `A_AUTH`.
- RFC 6762 / RFC 6763 — mDNS and DNS-SD, used by wireless-debugging discovery.
- RFC 8446 — TLS 1.3, used by the `A_STLS` upgrade.
- The SPAKE2 password-authenticated key exchange, used by `adb pair`.

### OWASP

- OWASP MASVS — https://mas.owasp.org/MASVS/
- OWASP MASTG — https://mas.owasp.org/MASTG/
- MASTG "Android Basic Security Testing" — every setup step assumes this chapter's transport.

### Vulnerability classes worth reading about

Rather than cite identifiers this chapter has not verified, these are the *classes* to search for by
name:

- **Self-propagating malware over exposed ADB port 5555** — widely reported from 2018 onward against
  set-top boxes, TVs and development boards with `ro.adb.secure=0`. Search "ADB.Miner" and
  "ADB worm 5555".
- **Pre-authorised vendor keys in shipping images** — recurring in embedded Android teardowns.
- **`android:debuggable="true"` in production releases** — a standing category in app store
  scanning and in MASTG.

### Related chapters

| Chapter | Relationship |
|---|---|
| [77-UsefulCommands](../77-UsefulCommands/README.md) | Owns the command set. This chapter owns the transport beneath it |
| [09-Android-App-Internals](../09-Android-App-Internals/README.md) | Owns the package-manager half of the install; §3.14 owns the transport half |
| [10-APK-Internals](../10-APK-Internals/README.md) | What `install-commit` verifies |
| [21-App-Sandbox](../21-App-Sandbox/README.md) | The app sandbox that `shell` is deliberately outside of |
| [22-SELinux](../22-SELinux/README.md) | The `adbd` and `shell` domains, and the AVC in §3.9.4 |
| [23-Permissions](../23-Permissions/README.md) | `platform.xml`, `privapp-permissions`, and where `shell`'s 183 grants come from |
| [24-IPC](../24-IPC/README.md) | Where `exec:` and `abb_exec:` hand off |
| [25-Binder](../25-Binder/README.md) | `cmd` and `shellCommand()`, and FD passing over Binder |
| [06-Android-Architecture](../06-Android-Architecture/README.md) | `init`, properties and the service startup chain |
| [02-Linux-Basics](../02-Linux-Basics/README.md) | UIDs, groups, capabilities and `/proc` |
| [34-Cryptography](../34-Cryptography/README.md) | RSA, PKCS#1 v1.5 padding and why the unhashed token still works |
| [35-SSL](../35-SSL/README.md) | The TLS that `A_STLS` upgrades to |
| [37-RootDetection](../37-RootDetection/README.md) | Apps that check `adb_enabled` and `ro.debuggable`, and how to defeat them |
| [53-Frida](../53-Frida/README.md) | Reaches `frida-server` through `adb forward` |
| [62-Magisk](../62-Magisk/README.md) | Where `su` comes from when `adb root` is refused |
| `61-Fastboot` | The other "only way to talk to a device" — a completely separate protocol, with no Android userspace behind it |
