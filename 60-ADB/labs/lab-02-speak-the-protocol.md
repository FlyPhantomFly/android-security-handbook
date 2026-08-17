# Lab 02 — Speak the protocol

> **Objective:** connect to `adbd` and drive it with **no `adb` client, no `adb` server, and no
> third-party libraries** — perform `A_CNXN`, handle `A_AUTH`, open a stream, run a command, and
> close cleanly. Then extend it to do something the `adb` binary cannot do for you.

**Difficulty:** Intermediate
**Time:** 2–4 hours (longer if you write the client from scratch, which you should)
**Prerequisites:** [Lab 01](lab-01-read-the-wire.md), [60-ADB §3.1–§3.9](../README.md#3-deep-internal-working)
**You will need:** Python 3.6+, an emulator or a spare device that listens on TCP, and
`~/.android/adbkey` (which `adb` generates the first time you run it).

---

## 0. Why this is the lab that matters

You can read about a protocol for a week and still not own it. You own it the first time your own
socket receives a reply you predicted.

There is also a practical reason. Every ADB tool you will ever use — `adb` itself, `scrcpy`,
`frida`'s device backend, MobSF's automation, every CI harness — is a client of this protocol. When
one of them behaves strangely, the question "what is it actually putting on the wire" becomes
answerable only if you have been there yourself.

And there is a security reason. If you find something that speaks ADB on a port where it should not
be — an IoT device, a container, a kiosk — you will want to enumerate it carefully and without
side effects. The stock `adb` client is a blunt instrument that will happily offer your public key
and raise a dialog on somebody else's screen. Your own client does exactly what you tell it.

---

## 1. Setup and safety rules

### 1.1 Target

Use an emulator. It listens on TCP, requires no authentication, and is disposable.

```bash
# host
"$ANDROID_HOME/emulator/emulator" -avd <name> -no-window -no-audio -no-snapshot -no-boot-anim &
adb wait-for-device && adb devices -l
```

`emulator-5554` → port **5555**.

### 1.2 The rules for this lab

> **⚠️ Warning — read these before you write a line of code.**
>
> 1. **Do not run `adb tcpip` on a device you care about.** It creates a real, persistent
>    network exposure. This lab needs a TCP-reachable `adbd`; an emulator already is one.
> 2. **Never send `A_AUTH(RSAPUBLICKEY)` to a device you do not own.** That message raises the
>    "Allow USB debugging?" dialog on somebody else's screen, and if they tap Allow, your key is
>    permanently in their `adb_keys`. Every client you write should have an explicit switch for it,
>    defaulting to off when you are enumerating.
> 3. **Never print, log, copy or commit your private key.** `~/.android/adbkey` is an unencrypted
>    credential. Your client reads it, uses it to make one signature, and that is all. It must never
>    end up in a transcript, a screenshot, a repository or a ticket.
> 4. **Do not put `root:`, `tcpip:`, `usb:`, `remount:` or `reboot:` in an enumeration sweep.** They
>    take effect the moment `adbd` dispatches them.

---

## 2. Part A — the framing

Start a file called `myadb.py`. You are going to build it in five parts, testing after each.

### 2.1 Constants

```python
#!/usr/bin/env python3
"""myadb.py -- an ADB client, written from the specification."""

import socket
import struct
import sys

# Four ASCII characters read as a little-endian uint32.
A_CNXN = 0x4E584E43   # "CNXN"
A_AUTH = 0x48545541   # "AUTH"
A_OPEN = 0x4E45504F   # "OPEN"
A_OKAY = 0x59414B4F   # "OKAY"
A_WRTE = 0x45545257   # "WRTE"
A_CLSE = 0x45534C43   # "CLSE"
A_STLS = 0x534C5453   # "STLS"

NAMES = {A_CNXN: "A_CNXN", A_AUTH: "A_AUTH", A_OPEN: "A_OPEN",
         A_OKAY: "A_OKAY", A_WRTE: "A_WRTE", A_CLSE: "A_CLSE",
         A_STLS: "A_STLS"}

A_VERSION = 0x01000001
MAX_PAYLOAD = 256 * 1024
```

**Check yourself:** derive `A_CNXN`'s value from the string `"CNXN"` on paper before you trust the
constant. If you cannot, go back to Lab 01 §2.

### 2.2 Pack and unpack

```python
def checksum(payload):
    """protocol.txt calls this a CRC32. It is a byte sum, and nothing checks
    it. We compute it honestly anyway."""
    return sum(payload) & 0xFFFFFFFF


def pack(command, arg0, arg1, payload=b""):
    return struct.pack("<6I", command, arg0, arg1, len(payload),
                       checksum(payload), command ^ 0xFFFFFFFF) + payload
```

`"<6I"` is the whole header format: `<` little-endian, `6I` six unsigned 32-bit integers. If you
ever find yourself hand-rolling byte order, stop and use this.

```python
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("peer closed after %d of %d bytes" % (len(buf), n))
        buf += chunk
    return buf


def recv_message(sock):
    head = recv_exact(sock, 24)
    command, arg0, arg1, length, csum, magic = struct.unpack("<6I", head)
    if magic != (command ^ 0xFFFFFFFF):
        raise IOError("framing lost: command=0x%08x magic=0x%08x"
                      % (command, magic))
    payload = recv_exact(sock, length) if length else b""
    return command, arg0, arg1, payload
```

> **The `recv_exact` loop is not optional.** `socket.recv(24)` can legally return fewer than 24
> bytes. Every hand-written ADB client that "works on the emulator and breaks over the network"
> made this mistake.

### ✅ Checkpoint A

```python
h = pack(A_OPEN, 1, 0, b"shell:id\x00")
print(h[:24].hex())
```

You should get `4f50454e0100000000000000090000001f030000b0afbab1` — byte-for-byte the header from
Lab 01. If it differs, compare field by field with `decode_header.py --explain`.

---

## 3. Part B — connect

```python
def connect(sock, features="cmd,stat_v2,ls_v2"):
    banner = ("host::features=%s" % features).encode() + b"\x00"
    sock.sendall(pack(A_CNXN, A_VERSION, MAX_PAYLOAD, banner))

    while True:
        command, arg0, arg1, payload = recv_message(sock)
        print("<- %s arg0=0x%08x arg1=0x%08x len=%d"
              % (NAMES.get(command, hex(command)), arg0, arg1, len(payload)))

        if command == A_CNXN:
            text = payload.rstrip(b"\x00").decode("utf-8", "replace")
            return text, min(arg1, MAX_PAYLOAD) if arg1 else 4096

        if command == A_STLS:
            raise RuntimeError("this adbd requires TLS (wireless debugging)")

        if command == A_AUTH:
            raise NotImplementedError("Part C")

        raise IOError("unexpected message during connect")
```

Try it:

```python
if __name__ == "__main__":
    s = socket.create_connection(("127.0.0.1", 5555), timeout=10)
    banner, maxdata = connect(s)
    print("banner:", banner)
    print("maxdata:", maxdata)
```

### ✅ Checkpoint B

Against an emulator you should get the device banner straight back, because emulator images ship
`ro.adb.secure=0`. Confirm that:

```bash
# host
adb -s emulator-5554 shell getprop ro.adb.secure     # 0
```

Now **write down what you have just learned about that device's security posture**, in one sentence.
You connected to a debug service and got a session with no credential. If that device were on a
network instead of on loopback, that is a critical finding, and you have just demonstrated it in
fifteen lines.

Parse the banner properly — split on `:` into systemtype, serial and properties, then split the
properties on `;` and `=`. How many features did it advertise? Compare with:

```bash
# host
adb features
```

---

## 4. Part C — authenticate

This is the part with the security content. Take your time.

### 4.1 What you are implementing

```
device -> host   A_AUTH(arg0=1 ADB_AUTH_TOKEN,        20 random bytes)
host   -> device A_AUTH(arg0=2 ADB_AUTH_SIGNATURE,    256 bytes)
device -> host   A_CNXN(...)                          if it verified
                 A_AUTH(arg0=1, a NEW token)          if it did not
host   -> device A_AUTH(arg0=3 ADB_AUTH_RSAPUBLICKEY, ~709 bytes) — RAISES A DIALOG
```

The signature is **RSA PKCS#1 v1.5 over `SHA1-DigestInfo || token`**, and the token is *not hashed*
— it is already 20 bytes, the size of a SHA-1 digest, and the reference implementation feeds it
straight into `RSA_sign(NID_sha1, ...)`, which prepends the DigestInfo and pads.

### 4.2 Read the key

`~/.android/adbkey` is an **unencrypted PKCS#8 PEM**. You need `n` and `d` out of it. Parsing DER by
hand is about twenty lines and is worth doing once:

```python
import base64, os

def der_read(buf, pos):
    tag = buf[pos]; pos += 1
    first = buf[pos]; pos += 1
    if first & 0x80:
        nb = first & 0x7F
        length = int.from_bytes(buf[pos:pos + nb], "big"); pos += nb
    else:
        length = first
    return tag, buf[pos:pos + length], pos + length


def der_ints(seq):
    out, pos = [], 0
    while pos < len(seq):
        tag, body, pos = der_read(seq, pos)
        out.append(int.from_bytes(body, "big") if tag == 0x02 else None)
    return out


def load_private_key(path):
    """-> (n, d). Never returns, prints or logs the key file itself."""
    pem = open(path, "rb").read()
    der = base64.b64decode(b"".join(
        l for l in pem.split(b"\n") if l and not l.startswith(b"-----")))
    _t, outer, _ = der_read(der, 0)

    # PKCS#1 "RSA PRIVATE KEY": version, n, e, d, p, q, dp, dq, qinv
    ints = der_ints(outer)
    if len(ints) >= 9 and ints[0] == 0 and ints[1] and ints[1] > 255:
        return ints[1], ints[3]

    # PKCS#8 "PRIVATE KEY": version, AlgorithmIdentifier, OCTET STRING(pkcs1)
    pos = 0
    _t, _v, pos = der_read(outer, pos)
    _t, _a, pos = der_read(outer, pos)
    _t, inner, pos = der_read(outer, pos)
    _t, pk1, _ = der_read(inner, 0)
    ints = der_ints(pk1)
    return ints[1], ints[3]
```

> **⚠️ From this point on, your program holds a credential in memory.** Do not add a `print(pem)`
> "just to check". Do not paste your key into a chat window to ask for help. If you must debug,
> print `n.bit_length()` — that is `2048` and reveals nothing.

### 4.3 Sign

```python
SHA1_DIGESTINFO = bytes([
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
    0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
])

def sign_token(token, n, d):
    assert len(token) == 20, "the token is always 20 bytes"
    k = (n.bit_length() + 7) // 8            # 256 for RSA-2048
    t = SHA1_DIGESTINFO + token              # 35 bytes
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")
```

That is the whole of PKCS#1 v1.5 signing: build `00 01 FF…FF 00 || DigestInfo || digest` to exactly
the modulus length, then raise it to the private exponent modulo `n`. Python's `pow(m, d, n)` does
the modular exponentiation for you.

### 4.4 Verify your own signature before you send it

This is the step most people skip, and it is the one that turns "it did not work" into "I know
exactly which byte is wrong". You can check the signature **offline**, against your own public key,
with no device involved.

```python
def load_public_blob(path):
    """The 524-byte mincrypt RSAPublicKey struct, decoded from adbkey.pub."""
    data = open(path, "rb").read().split()[0]
    blob = base64.b64decode(data)
    assert len(blob) == 524, "expected 524 bytes, got %d" % len(blob)
    words = int.from_bytes(blob[0:4], "little")            # 64 for RSA-2048
    n = int.from_bytes(blob[8:8 + words * 4], "little")    # LITTLE-endian words
    e = int.from_bytes(blob[520:524], "little")            # 3 or 65537
    return n, e, words


def selftest(keypath):
    n, d = load_private_key(keypath)
    pn, e, words = load_public_blob(keypath + ".pub")
    assert pn == n, "adbkey and adbkey.pub are not a pair"
    token = bytes(range(20))
    sig = sign_token(token, n, d)
    recovered = pow(int.from_bytes(sig, "big"), e, n).to_bytes(256, "big")
    expected = (b"\x00\x01" + b"\xff" * (256 - 35 - 3) + b"\x00"
                + SHA1_DIGESTINFO + token)
    assert recovered == expected, "signature does not verify"
    print("selftest OK: %d-bit key, %d modulus words, e=%d" % (n.bit_length(), words, e))
```

Run it. It should print `selftest OK: 2048-bit key, 64 modulus words, e=65537` and nothing else.

> **Note what you just proved without touching a device.** You produced a signature and verified it
> with the matching public key, using the exact padding and DigestInfo `adbd` will use. If the
> device later rejects it, the problem is that your key is not authorised — not that your crypto is
> wrong. Separating those two failure modes in advance saves hours.

### 4.5 Wire it in

```python
def connect(sock, keypath, offer_key=False, features="cmd,stat_v2,ls_v2"):
    banner = ("host::features=%s" % features).encode() + b"\x00"
    sock.sendall(pack(A_CNXN, A_VERSION, MAX_PAYLOAD, banner))
    tries = 0
    while True:
        command, arg0, arg1, payload = recv_message(sock)
        if command == A_CNXN:
            return payload.rstrip(b"\x00").decode("utf-8", "replace"), \
                   (min(arg1, MAX_PAYLOAD) if arg1 else 4096)
        if command == A_STLS:
            raise RuntimeError("adbd requires TLS -- wireless debugging pairing")
        if command == A_AUTH and arg0 == 1:
            tries += 1
            if tries == 1:
                n, d = load_private_key(keypath)
                sock.sendall(pack(A_AUTH, 2, 0, sign_token(payload, n, d)))
                continue
            print("signature REJECTED -- this key is not in the device's adb_keys")
            if not offer_key:
                raise RuntimeError("refusing to offer the public key")
            pub = open(keypath + ".pub", "rb").read().strip() + b"\x00"
            sock.sendall(pack(A_AUTH, 3, 0, pub))
            print("watch the DEVICE SCREEN -- a consent dialog is now showing")
            continue
        raise IOError("unexpected %s" % NAMES.get(command, hex(command)))
```

### ✅ Checkpoint C

- `selftest()` passes.
- Against the emulator, nothing changes (no `A_AUTH` is sent) — and you understand why.
- If you have a spare device you own, authorise it once with the real `adb`, then run your client
  against it and watch the `A_AUTH(TOKEN)` → `A_AUTH(SIGNATURE)` → `A_CNXN` sequence complete.

**Do not test the rejection path on a device you do not own.**

---

## 5. Part D — open a stream

```python
def run_service(sock, service, local_id=1, maxdata=4096, timeout=8.0):
    payload = service.encode("utf-8") + b"\x00"
    sock.sendall(pack(A_OPEN, local_id, 0, payload))

    remote_id = None
    out = b""
    sock.settimeout(1.0)
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            command, arg0, arg1, data = recv_message(sock)
        except socket.timeout:
            continue
        except EOFError:
            break

        if arg1 != local_id:
            # Not our stream. adbd interleaves; demultiplex on arg1.
            continue

        if command == A_OKAY:
            if remote_id is None:
                remote_id = arg0
                print("stream up: local=%d remote=%d" % (local_id, remote_id))
            continue
        if command == A_WRTE:
            out += data
            # MANDATORY. The window is exactly one message.
            sock.sendall(pack(A_OKAY, local_id, arg0))
            continue
        if command == A_CLSE:
            if remote_id is None:
                print("service REFUSED (A_CLSE arg0=%d)" % arg0)
            sock.sendall(pack(A_CLSE, local_id, arg0))
            break
    sock.settimeout(None)
    return remote_id, out
```

Three details in there are the whole lab, and all three are things people get wrong:

1. **`if arg1 != local_id: continue`.** `adbd` may still be finishing a previous stream. Without
   this, a stale `A_CLSE` looks like a refusal.
2. **The `A_OKAY` after every `A_WRTE`.** Omit it and the device stops sending.
3. **`A_CLSE` with `arg0 == 0` before any `A_OKAY`** is a refusal, and that is the only signal you
   get.

### ✅ Checkpoint D

```python
s = socket.create_connection(("127.0.0.1", 5555), timeout=10)
banner, maxdata = connect(s, os.path.expanduser("~/.android/adbkey"))
rid, out = run_service(s, "shell:id", maxdata=maxdata)
print(out.decode())
```

You should see `uid=2000(shell) … context=u:r:shell:s0`.

**Congratulations — you have an ADB client.** Compare its output with `adb shell id` and confirm
they match.

---

## 6. Part E — do something `adb` will not do for you

Now use it for things the stock client makes awkward.

### 6.1 Enumerate the service strings

```python
SAFE_SERVICES = [
    "shell:", "shell:id", "shell,v2,raw:id", "exec:id",
    "sync:", "jdwp", "track-jdwp", "framebuffer:",
    "reverse:list-forward", "sink:", "definitelynotaservice:",
]

for svc in SAFE_SERVICES:
    s = socket.create_connection(("127.0.0.1", 5555), timeout=10)
    connect(s, os.path.expanduser("~/.android/adbkey"))
    rid, out = run_service(s, svc, timeout=2.0)
    print("%-24s %s" % (svc, "AVAILABLE" if rid else "refused"))
    s.close()
```

> **⚠️ The list above is deliberately safe.** `root:`, `unroot:`, `tcpip:`, `usb:`, `remount:` and
> `reboot:` all take effect immediately. Do not add them to a sweep.

### 6.2 See the shell-v2 framing

```python
s = socket.create_connection(("127.0.0.1", 5555), timeout=10)
connect(s, keypath, features="shell_v2,cmd")
rid, out = run_service(s, "shell,v2,raw:echo hi")
print(out.hex())
```

You should get something beginning `010300000068690a` — packet id `1` (stdout), length `3`
little-endian, then `hi\n` — followed by a packet with id `3` carrying the exit status. Compare with
plain `shell:echo hi`, which returns the bare bytes `68690a` and **no exit code at all**.

Now write a tiny parser for the v2 framing and print stdout, stderr and the exit code separately.
That is about fifteen lines, and it is the difference between a toy and a usable tool.

### 6.3 Verify the flow-control rule by breaking it

Deliberately send two `A_WRTE`s in a row without waiting for the `A_OKAY`, on an `exec:cat` stream,
and see what happens. Document the result. (On some builds it works because the peer is generous;
on others the connection dies. Either way you now know why the rule exists rather than having been
told.)

### 6.4 Open two streams at once

Open `shell:logcat` and `shell:id` on the same connection with different local ids, and interleave
reading them. This is the moment the multiplexing stops being theoretical: you will see messages for
both streams arriving on one socket, distinguished only by `arg1`.

### ✅ Checkpoint E

- A service table for your target.
- A working shell-v2 parser that reports an exit code.
- Two concurrent streams on one connection, correctly demultiplexed.

---

## 7. Compare with the reference implementation

Only now, read [`../scripts/adb-mini-client.py`](../scripts/adb-mini-client.py). It does everything
above with more error handling and a lot more commentary. Diff its approach against yours:

- How does it decide whether to offer the public key?
- Why does it not advertise `shell_v2` by default?
- What does it do when it sees `A_STLS`, and why does it refuse to fake success?
- Read its "WHAT THIS WILL NOT TELL YOU" section and check that you agree with every limitation.

Then read [`../scripts/adb-install-transport.py`](../scripts/adb-install-transport.py) and find
`Stream._next_for_me()`. The comment there records a bug that was found by running the code: adbd
sent the `A_CLSE` for stream 1 after the `A_OPEN` for stream 2, and the naive client read it as a
refusal. If you implemented §5's `arg1` check, you never had that bug.

---

## 8. Hints

<details>
<summary>My header hex does not match the one from Lab 01</summary>

Check the format string. `"<6I"` — the `<` is essential, and without it Python uses native byte
order plus alignment padding, which will give you a 24-byte string that is subtly wrong on some
platforms and right on others.

</details>

<details>
<summary>The device sends A_AUTH and my signature is rejected</summary>

Three possibilities, in order of likelihood:

1. Your key is genuinely not in the device's `adb_keys`. Authorise it once with the real `adb`.
2. You hashed the token. Do not. Feed the 20 bytes straight into the padding.
3. Your padding is the wrong length. `em` must be **exactly** the modulus size in bytes (256 for
   RSA-2048). Run `selftest()` from §4.4 — if that passes, your crypto is right and the problem is
   authorisation.

</details>

<details>
<summary>My client hangs after the first A_WRTE</summary>

You did not send the `A_OKAY`. The window is one message.

</details>

<details>
<summary>My client reports every service as refused</summary>

You are probably reading the `A_CLSE` from the *previous* stream. Add the
`if arg1 != local_id: continue` check, or open a fresh connection per service as §6.1 does.

</details>

<details>
<summary>struct.error: unpack requires a buffer of 24 bytes</summary>

`sock.recv(24)` returned fewer than 24 bytes. Use the `recv_exact` loop.

</details>

<details>
<summary>I get A_STLS and nothing works</summary>

Your target is in wireless-debugging mode and requires TLS with a pairing-derived certificate. Your
`adbkey` cannot complete it. Use a target in classic mode, or an emulator.

</details>

---

## 9. Success criteria

You have finished this lab when:

1. Your own client, with no third-party dependencies, connects to `adbd`, completes `A_CNXN`,
   handles `A_AUTH` where required, opens a stream, runs `id`, and closes cleanly.
2. `selftest()` verifies your own signature against your own public key, offline.
3. You can explain, without notes: why the token is not hashed; why `em` must be exactly 256 bytes;
   what the 524-byte public-key blob contains; and why every 2048-bit ADB public key's base64 starts
   with `QAAA`.
4. Your client demultiplexes on `arg1` and you can say what breaks if it does not.
5. Your client sends an `A_OKAY` for every `A_WRTE` and you can say what breaks if it does not.
6. You have a service-availability table for a target, produced without touching any destructive
   service string.
7. You can parse the shell-v2 framing and report an exit code.
8. You can state, in one sentence each, why rule 2 and rule 3 in §1.2 exist.

---

## 10. Going further

- **Implement `sync:`.** Read `packages/modules/adb/SYNC.TXT` and implement `STAT`, `LIST` and
  `RECV`. You will have written `adb pull` in about eighty lines.
- **Implement the install session.** Three streams, as in §3.14 of the chapter. Then compare with
  [`../scripts/adb-install-transport.py`](../scripts/adb-install-transport.py).
- **Speak the smart-socket protocol** to the local `adb` server on 5037 as well, and write a tool
  that lists devices without shelling out to `adb`.
- **Handle `delayed_ack`.** Modern devices advertise it; work out from the AOSP source what changes
  and whether your client could use it.
- **Write it in a language with no big-integer type** and discover why the reference implementation
  links OpenSSL.

---

## Next

**[Lab 03 — Posture and exposure](lab-03-posture-and-exposure.md)** — now that you can talk to
`adbd`, learn to measure what talking to it is worth, and to rate it honestly.
