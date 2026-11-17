# Lab 01 — Read the wire

> **Objective:** decode real ADB protocol headers by hand, prove for yourself which fields are
> load-bearing and which are decoration, and map a complete `adb shell` session onto its message
> sequence — without writing any code.

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** [60-ADB §2](../README.md#2-high-level-architecture),
[02-Linux-Basics](../../02-Linux-Basics/README.md) for hex and byte order
**You will need:** a workstation with `adb`, Python 3, and either an Android emulator or a spare
device you own. **You do not need root, and you do not need to modify any device.**

---

## 0. Why this lab exists

Binary protocols look intimidating until you decode one message. After that they are tedious, which
is a much better state to be in.

This lab does not ask you to write a client. It asks you to look at bytes that a real device
actually sent, work out what they mean, and check your working. Everything you decode here you will
meet again in Lab 02, where you will generate the same bytes yourself.

There is one thing to internalise above all others: **the ADB header is six little-endian 32-bit
integers and nothing else.** Every mystery in this protocol dissolves once that is automatic.

---

## 1. Setup

### 1.1 A target you can throw away

If you have an emulator, use it. It listens on TCP already, it requires no authentication, and
nothing you do to it matters.

```bash
# host — list your AVDs
"$ANDROID_HOME/emulator/emulator" -list-avds

# host — boot one headless, without touching its saved state
"$ANDROID_HOME/emulator/emulator" -avd <name> -no-window -no-audio -no-snapshot -no-boot-anim &

# host — wait for it
adb wait-for-device
adb devices -l
```

`emulator-5554` means its ADB port is `5555`. `emulator-5556` means `5557`, and so on.

If you have no emulator, you can still do **every part of this lab except §5**, using a physical
device over USB.

> **Do not run `adb tcpip` on a phone you care about** to complete §5. Turning USB debugging into
> a network service on whatever network the device joins next is a real, persistent exposure. Use an
> emulator, or skip §5 and come back to it when you have a spare device.

### 1.2 Check your tools

```bash
# host
adb version
python3 --version
python3 -B ../examples/decode_header.py 4f4b4159010000000f0000000000000000000000b0b4bea6
```

That last command should print an `A_OKAY` with `magic … OK`. If it does, you are ready.

---

## 2. The header, on paper

Before any tooling, do this by hand. Get a pen.

Here is a real header, captured from a device:

```
4f 50 45 4e  01 00 00 00  00 00 00 00  11 00 00 00  25 06 00 00  b0 af ba b1
```

### Step 2.1 — split it into six fields

The header is exactly 24 bytes and exactly six fields, each a 32-bit integer.

| Bytes | Field |
|---|---|
| `4f 50 45 4e` | `command` |
| `01 00 00 00` | `arg0` |
| `00 00 00 00` | `arg1` |
| `11 00 00 00` | `data_length` |
| `25 06 00 00` | `data_check` |
| `b0 af ba b1` | `magic` |

### Step 2.2 — convert each from little-endian

Little-endian means **the least significant byte comes first**. To read a value, reverse the four
bytes and then read them as hex.

- `4f 50 45 4e` reversed is `4e 45 50 4f` → **`0x4e45504f`**
- `01 00 00 00` reversed is `00 00 00 01` → **`0x00000001`** = 1
- `00 00 00 00` → **0**
- `11 00 00 00` reversed is `00 00 00 11` → **`0x11`** = 17
- `25 06 00 00` reversed is `00 00 06 25` → **`0x625`** = 1573
- `b0 af ba b1` reversed is `b1 ba af b0` → **`0xb1baafb0`**

### Step 2.3 — identify the command

Read the first four bytes as **ASCII** instead:

```
0x4f = 'O'   0x50 = 'P'   0x45 = 'E'   0x4e = 'N'
```

`OPEN`. So this is `A_OPEN`.

> **This is the single fact that makes every ADB constant readable.** `A_OPEN` is defined as
> `0x4e45504f` in AOSP not because someone picked a random number, but because that is the ASCII
> string `OPEN` read as a little-endian integer. Do the same for `CNXN`, `WRTE`, `OKAY`, `CLSE`,
> `AUTH`, `STLS` and `SYNC` — all eight.

### Step 2.4 — verify the magic

`magic` must equal `command ^ 0xffffffff`.

```
  0x4e45504f
^ 0xffffffff
------------
  0xb1baafb0
```

XOR with all-ones is just a bitwise NOT, so you can do it a nibble at a time: `4 → b`, `e → 1`,
`4 → b`, `5 → a`, `5 → a`, `0 → f`, `4 → b`, `f → 0`. That gives `0xb1baafb0`. It matches.

**Now check your working:**

```bash
# host
python3 -B ../examples/decode_header.py --explain 4f50454e01000000000000001100000025060000b0afbab1
```

### Checkpoint 2

You should be able to say, without looking anything up:

- How many bytes is an ADB header, and how many fields?
- Which byte order, and what does that mean for reading `01 00 00 00`?
- Why is `A_OPEN` the number `0x4e45504f`?
- What is `magic` for, and what is it **not** for?

---

## 3. Decode these six by hand

Each of these is a real header captured from a live device. For each one, write down: the command
name, `arg0`, `arg1`, the payload length, and one sentence saying what the message means. Then check
with `decode_header.py`.

**Do not check until you have written all six.**

```
(a) 434e584e 01000001 00000400 21000000 030c0000 bcb1a7b1
(b) 4f4b4159 5c000000 01000000 00000000 00000000 b0b4bea6
(c) 57525445 5c000000 01000000 14010000 00000000 a8adabba
(d) 434c5345 00000000 01000000 00000000 00000000 bcb3acba
(e) 41555448 01000000 00000000 14000000 00000000 beaaabb7
(f) 434e584e 01000001 00000400 8b010000 00000000 bcb1a7b1
```

<details>
<summary>Answers — open only after you have written yours</summary>

**(a)** `A_CNXN`. `arg0 = 0x01000001` is the protocol version; `arg1 = 0x00040000` = 262144 is
maxdata (256 KiB). 33 bytes of payload follow — a banner. `data_check = 0x0c03` = 3075. **This is a
host announcing itself.**

**(b)** `A_OKAY`. Sender's id 0x5c = 92, peer's id 1. No payload. **Either "your stream is open" or
"I consumed your last write."** You cannot tell which from the header alone — you need the
surrounding sequence.

**(c)** `A_WRTE` on the same stream pair. 0x114 = 276 bytes of payload. **Stream data from the
device.**

**(d)** `A_CLSE` with `arg0 = 0`. **A refusal.** The service named in the corresponding `A_OPEN` was
not available, and there is no error message or code anywhere in this protocol to tell you why.

**(e)** `A_AUTH` with `arg0 = 1` = `ADB_AUTH_TOKEN`, 20 bytes of payload. **The device is
challenging the host to prove it holds an authorised key.**

**(f)** `A_CNXN` again, but 395 bytes of payload and `data_check = 0`. **The device's reply.** Note
the zero checksum on a 395-byte payload — see §4.

</details>

### Checkpoint 3

Six correct out of six. If (b) tripped you up, re-read §3.3 of the chapter: `A_OKAY` genuinely does
double duty and the header cannot distinguish the two uses.

---

## 4. Prove the checksum is dead

This is the part of the lab that teaches you to distrust documentation and trust bytes.

AOSP's own `packages/modules/adb/protocol.txt` describes `data_check` as a CRC32 of the payload.

### Step 4.1 — compute what the host sent

Header (a) above had `data_check = 0x0c03` and 33 bytes of payload. The payload was
`host::features=cmd,stat_v2,ls_v2` plus one NUL byte.

Compute the **sum of the byte values**:

```bash
# host
python3 -c "
s = b'host::features=cmd,stat_v2,ls_v2\x00'
print('length', len(s))
print('byte sum', sum(s), hex(sum(s)))
"
```

You should get `33` and `3075` = `0xc03`. **It matches the header exactly.** So the field is a byte
sum, not a CRC32 — the documentation and the implementation disagree.

### Step 4.2 — see what the device sent

Header (f) had a 395-byte payload and `data_check = 0x00000000`. A 395-byte payload of printable
text cannot sum to zero.

**Therefore `adbd` does not compute the field at all.**

### Step 4.3 — confirm it on your own target

```bash
# host
python3 -B ../scripts/adb-mini-client.py --port 5555 --service "shell:id" -v 2>&1 \
  | grep '^<<'
```

Every incoming message should show `cksum=0x00000000`, including the ones with payloads.

### Checkpoint 4

Write one sentence explaining, to a colleague who has read `protocol.txt` and believes the field is
a CRC32, what you have just measured and what the consequence is. (Consequence: there is no
integrity protection on an ADB connection; `A_STLS` exists precisely because of that.)

---

## 5. Map a whole session

Now capture a complete session and identify every message.

```bash
# host
python3 -B ../scripts/adb-mini-client.py --port 5555 --service "shell:echo hello" -v 2>&1 \
  | tee /tmp/session.txt | grep -E '^(>>|<<)'
```

You should see eight messages. Fill in this table from your own capture:

| # | Direction | Command | arg0 | arg1 | len | What it means |
|---|---|---|---|---|---|---|
| 1 | `>>` | | | | | |
| 2 | `<<` | | | | | |
| 3 | `>>` | | | | | |
| 4 | `<<` | | | | | |
| 5 | `<<` | | | | | |
| 6 | `>>` | | | | | |
| 7 | `<<` | | | | | |
| 8 | `>>` | | | | | |

<details>
<summary>Expected shape</summary>

1. `>> A_CNXN` — host announces itself, ~33-byte banner
2. `<< A_CNXN` — device replies with its banner and feature list
3. `>> A_OPEN` — `arg0` is a local id you chose (1), `arg1` is 0, payload is
   `"shell:echo hello\x00"` = 17 bytes
4. `<< A_OKAY` — `arg0` is the device's id, `arg1` is your 1. **The stream now exists.**
5. `<< A_WRTE` — 6 bytes, `hello\n`
6. `>> A_OKAY` — your acknowledgement. **Without this the device would not send more.**
7. `<< A_CLSE` — the command exited
8. `>> A_CLSE` — you close your half

If you got an `A_AUTH` between 1 and 2, your target requires authentication (`ro.adb.secure=1`) —
that is fine and correct, and you have an extra two messages to account for.

</details>

### Step 5.1 — run it four times and watch the ids

```bash
# host
for i in 1 2 3 4; do
  python3 -B ../scripts/adb-mini-client.py --port 5555 --service "shell:true" 2>&1 \
    | grep 'remote-id'
done
```

The remote ids will be different every time. On the run used to write this chapter they were 11,
15, 27 and 92.

> **Lesson:** stream ids are per-connection, chosen by whoever opens the stream, and carry no
> meaning whatsoever. Never hard-code one, never infer anything from one, and never assume two
> captures are comparable by id.

### Step 5.2 — find the refusal

```bash
# host
python3 -B ../scripts/adb-mini-client.py --port 5555 --service "definitelynotaservice:" \
  --timeout 3 -v 2>&1 | grep -E '^(>>|<<)'
```

You should see `>> A_OPEN` followed immediately by `<< A_CLSE` with `arg0=0x00000000`, and nothing
else. No error string, no error code.

### Checkpoint 5

- Your eight-message table is complete and correct.
- You can state why message 6 is mandatory rather than polite.
- You can state what distinguishes "service refused" from "service does not exist" on the wire.
  (Nothing does.)

---

## 6. The one that is not the same protocol

A very common confusion: the thing on port **5037** is *not* the wire protocol.

```bash
# host — the smart-socket protocol. Text, with a 4-hex-digit length prefix.
printf '000chost:version' | nc 127.0.0.1 5037; echo
printf '000ehost:devices-l' | nc 127.0.0.1 5037; echo
```

Look at the reply: `OKAY`, then four hex digits of length, then the payload. **No 24-byte header
anywhere.** This is the protocol between your `adb` binary and your local `adb` server. The server
then speaks the binary wire protocol to the device on your behalf.

If `nc` is not available:

```bash
# host — same thing in Python
python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 5037))
req = b'host:version'
s.sendall(('%04x' % len(req)).encode() + req)
print(s.recv(1024))
"
```

### Checkpoint 6

Explain the difference between the two protocols in one sentence each, and name which one
`protocol.txt` documents and which one `SERVICES.TXT` documents.

---

## 7. Read the specification

Now that the bytes are familiar, the AOSP prose will read as confirmation rather than as
instruction.

- `packages/modules/adb/protocol.txt` — everything you just decoded.
- `packages/modules/adb/SERVICES.TXT` — §6's protocol, plus the full service-string list.

Read both on <https://cs.android.com/>. Note, as you read `protocol.txt`, the place where it
describes `data_check` as a CRC32 — and that you have measured otherwise. **That is a normal state
of affairs with specifications, and noticing it is the skill.**

---

## 8. Hints

<details>
<summary>My decode_header.py says "MISMATCH -- framing is lost"</summary>

You have either mistyped a byte, or you have copied a payload chunk instead of a header. A header is
exactly 24 bytes; if you pasted 48 hex characters you have 24 bytes, if you pasted more you have
included payload (which is fine — the tool will decode it too).

</details>

<details>
<summary>I cannot connect to 127.0.0.1:5555</summary>

Nothing is listening. Check `adb devices` shows an emulator, and that its name is `emulator-5554`
(port 5555). If it is `emulator-5556`, use `--port 5557`.

A physical device does **not** listen on TCP unless someone ran `adb tcpip`. Do not run it on a
device you care about; use an emulator.

</details>

<details>
<summary>My target sends A_AUTH and the client stops</summary>

Your target requires authentication. If it is a device you own and have authorised, the client will
sign with `~/.android/adbkey` automatically and succeed. If it says the signature was rejected, the
device does not trust your key — and you should **not** pass anything other than `--no-offer-key`
against a device you do not own, because offering your public key raises a consent dialog on
somebody else's screen.

</details>

<details>
<summary>Why does the payload sometimes not match the length?</summary>

The client truncates its hexdump preview at 96 bytes and prints `... N more payload bytes`. The
header's `data_length` is authoritative.

</details>

---

## 9. Success criteria

You have finished this lab when you can do all of the following **without notes**:

1. Name the six header fields in order, with sizes.
2. Convert `434e584e` to a command name, explaining the byte order.
3. Compute `magic` for any command.
4. State what `arg0` and `arg1` mean for a stream message, and which one you demultiplex on.
5. Explain why `A_CLSE` with `arg0 = 0` is a refusal, and what information the protocol does **not**
   give you about the reason.
6. State what `data_check` is documented as, what it is implemented as, and what it is worth.
7. Explain the difference between port 5037's protocol and the device wire protocol.
8. Draw the eight-message sequence for `adb shell echo hello` from memory.

---

## 10. Going further

- Decode a header for a message this lab did not produce: capture an `adb push` and find the
  `A_OPEN` carrying `sync:`, then look at the sync sub-protocol's own four-byte ids inside the
  `A_WRTE` payloads.
- Work out, on paper, the complete header for an `A_WRTE` on stream `(1, 92)` carrying the four
  bytes `test`, then verify it with `decode_header.py`.
- Read `packages/modules/adb/types.h` and find the function that computes `data_check`. Confirm from
  the source that it is a sum.

---

## Next

**[Lab 02 — Speak the protocol](lab-02-speak-the-protocol.md)** — stop reading bytes and start
producing them. You will connect to `adbd` with no `adb` client at all.
