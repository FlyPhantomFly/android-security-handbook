# Lab 02 — Parcel anatomy: decode the bytes, then break the token

> **Difficulty:** beginner to intermediate
> **Time:** 90–120 minutes
> **Needs:** `adb` and a device (no root). The NDK for Tasks 5–7; without it, the shipped captures
> in [`../examples/measured-binder-probe.txt`](../examples/measured-binder-probe.txt) let you do
> every decoding exercise offline.
> **Reading:** [README §3.7](../README.md#37-parcels--the-serialisation-format), [§3.9](../README.md#39-the-interface-token--a-security-control-not-a-formality), [§4.3](../README.md#43-parcelwriteinterfacetoken-and-enforceinterface)
> **Prerequisite lab:** [Lab 01](lab-01-service-list-and-call.md)

---

## Objective

1. Decode a real parcel by hand, byte by byte, and have the arithmetic close exactly.
2. State the wire format of `String16` from memory, including the three cases people get wrong.
3. Recognise an embedded `flat_binder_object` and explain what the kernel did to it in transit.
4. Read an exception header, including the remote stack trace, and extract reconnaissance from a
   refusal.
5. **Break the interface token deliberately** and observe the control fire — then explain precisely
   what it protects against and what it does not.

---

## Why this lab exists

The single most important property of a parcel is the one people find hardest to believe:

> **A parcel contains no type information at all.** No tags, no field names, no schema, and no
> length prefix on the message as a whole. It is a flat run of bytes, 4-byte aligned, and the reader
> must read exactly the fields the writer wrote, in exactly that order.

Everything else follows. It is why parcels are fast. It is why a `writeToParcel`/`CREATOR`
asymmetry is a security bug and not a cosmetic one. And it is the entire reason the interface token
exists, which is Task 8.

Until you have decoded one by hand, that property stays abstract. So: by hand first, tools second.

---

## Task 1 — Get a parcel

```bash
# adb shell
service call activity 1598968902
```

Measured on the reference device (Xiaomi M2101K6P, Android 11 / API 30):

```
Result: Parcel(
  0x00000000: 0000001c 006e0061 00720064 0069006f '....a.n.d.r.o.i.'
  0x00000010: 002e0064 00700061 002e0070 00410049 'd...a.p.p...I.A.'
  0x00000020: 00740063 00760069 00740069 004d0079 'c.t.i.v.i.t.y.M.'
  0x00000030: 006e0061 00670061 00720065 00000000 'a.n.a.g.e.r.....')
```

**Before you read on, notice a display quirk that trips everyone up once.**

`service` prints **32-bit words in host order**, not bytes. The first group `0000001c` is the four
bytes `1c 00 00 00` in memory — not `00 00 00 1c`. But the ASCII column on the right reads left to
right, byte by byte. So the word column is "backwards" relative to the character column, and both
are correct.

Get this wrong and every field you decode will be plausible and wrong. That is why
`../scripts/parcel-decode.py` handles the two dump formats separately and says which one it detected.

---

## Task 2 — Decode it by hand

Do this with a pencil before touching the script.

**Step 1.** The first four bytes are `1c 00 00 00`. Little-endian int32 = **28**.

**Step 2.** What is 28? Count the characters of `android.app.IActivityManager`:

```
a n d r o i d . a p p . I A c t i v i t y M a n a g e r
1 2 3 4 5 6 7 8 9 ...
```

Twenty-eight. So the int32 is a **character count**, not a byte count.

**Step 3.** 28 UTF-16LE code units = 56 bytes, from offset 4 to offset 59 (`0x3b`).

**Step 4.** Then a UTF-16 NUL: two more bytes, offsets 60–61.

**Step 5.** `4 + 56 + 2 = 62`. Parcels are 4-byte aligned, so pad up: **64**.

**Step 6.** The dump ends at offset `0x3f` = 63. Sixty-four bytes. **The arithmetic closes exactly.**

Now confirm:

```bash
# host
adb shell service call activity 1598968902 \
  | python3 -B ../scripts/parcel-decode.py - --layout str16
```

```
PARCEL -- 64 bytes, from service call hex dump (host-order words)

FIELDS (explicit layout)
  [0x0000] String16   'android.app.IActivityManager'
```

> **The `String16` wire format, which you now know**
> `int32` **character** count → that many UTF-16LE code units → a UTF-16 NUL → zero padding to the
> next 4-byte boundary.

**Three cases people get wrong, and you must not.**

| Case | Wire bytes | Total |
|---|---|---|
| `"ab"` | `02 00 00 00` `61 00 62 00` `00 00` + 2 pad | 12 bytes |
| `""` (empty) | `00 00 00 00` `00 00` + 2 pad | 8 bytes |
| `null` | `ff ff ff ff` and **nothing else** | 4 bytes |

Empty and null are **different**, and writing one where the reader expects the other does not raise
an error — it makes the reader consume the next field as a string length, and everything after it is
garbage. This is the most common hand-rolled-parcel bug there is.

---

## Task 3 — Decode a request parcel

Replies are the easy half. Now a request, with its interface token. From
[`../examples/measured-binder-probe.txt`](../examples/measured-binder-probe.txt), a hand-built
`checkService("activity")`:

```
  00000000: 00000000 ffffffff 54535953 1a000000  |........TSYS....|
  00000010: 61006e00 64007200 6f006900 64002e00  |a.n.d.r.o.i.d...|
  00000020: 6f007300 2e004900 53006500 72007600  |o.s...I.S.e.r.v.|
  00000030: 69006300 65004d00 61006e00 61006700  |i.c.e.M.a.n.a.g.|
  00000040: 65007200 00000000 08000000 61006300  |e.r.........a.c.|
  00000050: 74006900 76006900 74007900 00000000  |t.i.v.i.t.y.....|
```

**This dump is in the OTHER format.** `binder-probe` prints raw bytes, four to a group. So
`54535953` is the four bytes `54 53 59 53` in memory, which as a little-endian int32 is
`0x53595354` — the ASCII `'SYST'`. The `|TSYS|` in the character column is that same word read
byte by byte.

Walk it:

| Offset | Bytes | Field |
|---|---|---|
| `0x00` | `00 00 00 00` | int32 strict-mode thread policy |
| `0x04` | `ff ff ff ff` | int32 work-source uid = **−1** (unset) |
| `0x08` | `54 53 59 53` | int32 `0x53595354` = `'SYST'`, the parcel magic |
| `0x0c` | `1a 00 00 00` | int32 = 26 — the character count of `android.os.IServiceManager` |
| `0x10`–`0x47` | UTF-16 | the descriptor, its NUL, and padding |
| `0x48` | `08 00 00 00` | int32 = 8 — `"activity"` |
| `0x4c`–`0x5f` | UTF-16 | the argument |

Confirm:

```bash
# host
python3 -B ../scripts/parcel-decode.py ../examples/measured-binder-probe.txt --as token --no-hexdump | head -12
```

**Now answer two questions.**

1. The work-source field is `−1`. Where did that value come from — the kernel or the caller?
2. If a service called `Binder.getCallingWorkSourceUid()` and used the result in a permission check,
   how would you attack it?

The answer to both is in [README §3.11.4](../README.md#3114-the-identity-api-set-ranked), and it is
the single nastiest one-word-apart trap in the Binder API.

---

## Task 4 — Decode a reply containing an object

From the same capture, the reply to `checkService`:

```
  data_size    : 32 bytes
  offsets_size : 8 bytes  (1 embedded object)

  00000000: 00000000 852a6873 13010000 01000000  |.....*hs........|
  00000010: 00000000 00000000 00000000 0c000000  |................|
```

Walk it:

| Offset | Bytes | Field |
|---|---|---|
| `0x00` | `00 00 00 00` | int32 status — no exception |
| `0x04` | `85 2a 68 73` | `flat_binder_object.type` = `0x73682a85` = ASCII `'s' 'h' '*' 0x85` |
| `0x08` | `13 01 00 00` | `flags` = `0x113` |
| `0x0c` | `01 00 00 00` | the union — `handle` = 1 (8 bytes wide; upper half zero) |
| `0x14` | `00 …` | `cookie` = 0 |
| `0x1c` | `0c 00 00 00` | **not part of the struct** — the stability category `writeStrongBinder` appends |

```bash
# host
printf '  00000000: 00000000 852a6873 13010000 01000000  |x|\n  00000010: 00000000 00000000 00000000 0c000000  |x|\n' \
  | python3 -B ../scripts/parcel-decode.py - --as reply --no-hexdump | tail -8
```

```
EMBEDDED OBJECTS (found by scanning for the type magic)
  at offset 0x0004: BINDER_TYPE_HANDLE
      'sh*' -- a REMOTE reference
      flags  = 0x00000113  min-priority=19  ACCEPTS_FDS
      handle = 1   (meaningful ONLY in the receiving process)
      cookie = 0x0000000000000000
      then int32 12 -- the stability category writeStrongBinder() appends
```

**Three things to take from this.**

**The offsets array is separate, and it is 8 bytes long holding the single value 4.** It says: "there
is an object at byte 4 of this parcel." The driver used it to find the object and rewrite it. Without
it the object would be indistinguishable from four ordinary int32s.

**`handle = 1` is meaningless outside the receiving process.** Handle numbers are per-process. Handle
1 in `binder-probe` and handle 1 in your app are different objects. This is what the kernel's
translation step in [README §3.6](../README.md#36-the-single-copy-and-why-it-is-safe) produced.

**`flags = 0x113` decomposes.** `0x100` is `FLAT_BINDER_FLAG_ACCEPTS_FDS`; the low byte `0x13` = 19
is the node's minimum scheduling priority, which lives in `FLAT_BINDER_FLAG_PRIORITY_MASK` (`0xff`).

**Exercise.** Work out, from the table in
[README §3.7.3](../README.md#373-the-offsets-array-and-embedded-objects), what the four bytes would
be if this had been a file descriptor instead of a handle. What would the receiver then hold, and
what permission check would happen when it used it?

---

## Task 5 — Decode a refusal, and mine it

```bash
# host
adb shell service call notification 2 | python3 -B ../scripts/parcel-decode.py - --as reply --no-hexdump
```

Measured:

```
EXCEPTION HEADER
  [0x0000] int32      -1   <- SecurityException
  [0x0004] String16   'Disallowed call for uid 2000'   <- the exception message
  [0x0044] int32      996   <- stack-trace header size
  [0x0048] String16   493 chars of remote stack trace

  REMOTE STACK TRACE
    at com.android.server.notification.NotificationManagerService.checkCallerIsSystem(NotificationManagerService.java:8683)
    at com.android.server.notification.NotificationManagerService.access$4500(NotificationManagerService.java:310)
    at com.android.server.notification.NotificationManagerService$10.clearData(NotificationManagerService.java:3703)
    at android.app.INotificationManager$Stub.onTransact(INotificationManager.java:1132)
    at android.os.Binder.execTransactInternal(Binder.java:1162)
```

**Check the arithmetic yourself**, because it is a good test of whether you have understood the
format:

```
stack-trace header size = 996
                          = 4  (the size field itself)
                          + 4  (the String16 length field)
                          + 493 * 2  (the UTF-16 payload)
                          + 2  (the UTF-16 NUL)
                          = 4 + 4 + 986 + 2 = 996        OK
```

If that had not closed, your layout would have been wrong and the "stack trace" would have been
coincidental bytes.

**Now mine it.** From a call you were *refused*, you learned:

| | |
|---|---|
| The service saw uid **2000** | Our real uid. We did not put it in the parcel |
| The guard is `checkCallerIsSystem` | Now you know exactly what to defeat |
| **Transaction 2 is `clearData`** | A name for a bare integer, recovered from a refusal |
| `INotificationManager$Stub.onTransact` | An AIDL stub, so the token *is* enforced |

**Exercise.** Collect five refusals from five different services and build the table. Which gave up
the most? Is there a pattern in which services carry stack traces and which do not?

---

## Task 6 — Build the raw client

Everything so far used tools that write parcels for you. Now write one yourself.

```bash
# host — build
NDK=$ANDROID_SDK/ndk/25.2.9519653/toolchains/llvm/prebuilt/<your-host>/bin
$NDK/aarch64-linux-android21-clang -Wall -Wextra -O2 \
    ../examples/binder-probe.c -o /tmp/binder-probe

# host — push
adb push /tmp/binder-probe /data/local/tmp/
adb shell chmod 755 /data/local/tmp/binder-probe
```

It should compile with **no warnings**. If it does not, say so — the shipped version was built clean
with `-Wall -Wextra`.

```bash
# adb shell
/data/local/tmp/binder-probe
```

Measured output on the reference device:

```
Binder device nodes visible to uid 2000:
  /dev/binder              present=yes openable=yes
  /dev/hwbinder            present=yes openable=yes
  /dev/vndbinder           present=yes openable=no  reason=Permission denied
  /dev/binderfs/binder     present=yes openable=yes

Structure sizes on this ABI:
  sizeof(binder_write_read)        = 48
  sizeof(binder_transaction_data)  = 64
  sizeof(flat_binder_object)       = 24
  sizeof(binder_uintptr_t)         = 8

  protocol_version   : 8  (8 = 64-bit driver, 7 = 32-bit)
  mmap size          : 1040384 bytes (1016 KiB)  at 0x719bdf1000
                       = 1 MiB - 2 pages; page size is 4096
```

**Confirm the arithmetic.** `1048576 − (4096 × 2) = 1040384`. That single number is behind every
`TransactionTooLargeException` in Android, and Lab 04 is about it.

> **If `/data/local/tmp` execution is blocked** — some vendor builds refuse `execve` there — invoke
> the loader explicitly instead:
> ```bash
> adb shell /system/bin/linker64 /data/local/tmp/binder-probe
> ```

---

## Task 7 — Send a parcel you wrote yourself

```bash
# adb shell
/data/local/tmp/binder-probe --getservice activity
```

You will see the request parcel from Task 3 constructed live, sent to handle 0, and answered. No
libbinder was involved: the bytes were written by hand by 300 lines of C.

Then a real method call, resolved through servicemanager:

```bash
# adb shell
/data/local/tmp/binder-probe --call notification 2
```

Watch the four steps it prints. Step 2 is the interesting one — the tool asks the object for its own
descriptor rather than being told, which is exactly what `service call` does and exactly what
`RawBinderClient.getDescriptor()` does.

---

## Task 8 — Break the interface token on purpose

This is the point of the lab.

```bash
# adb shell — correct handle, correct code, WRONG interface token
/data/local/tmp/binder-probe --call notification 2 --token android.os.IServiceManager
```

Measured:

```
STEP 3 -- send transaction code 2 with a DELIBERATELY WRONG token
  the object says its interface is : "android.app.INotificationManager"
  we are claiming                  : "android.os.IServiceManager"
...
STEP 4 -- decode the reply's exception header
  exception code : -1  (SecurityException)
  message        : "Binder invocation to an incorrect interface"
```

**Compare the two refusals side by side.** This is the whole lesson:

| Command | Reply |
|---|---|
| `--call notification 2` | `SecurityException: "Disallowed call for uid 2000"` |
| `--call notification 2 --token android.os.IServiceManager` | `SecurityException: "Binder invocation to an incorrect interface"` |

The first got past the token check and was refused on **identity**. The second never got that far.
Two different controls, two different messages, both `SecurityException`.

**Now answer these properly, in writing.**

1. Why is a mismatched token a **security** problem and not a parsing problem? Construct a concrete
   example: two interfaces where the same bytes are valid for both and mean different things.
2. The descriptor is a public string, obtainable from any object with one transaction. So what does
   the token actually stop?
3. What kind of service has **no** token check, and how did you find them in Lab 01?
4. Would encrypting or randomising the descriptor make the token an authentication mechanism? Why
   not?

Model answers are in [README §3.9](../README.md#39-the-interface-token--a-security-control-not-a-formality)
and [FAQ 7](../faq.md), but write yours first.

---

## Task 9 — Find a parcel asymmetry

The reason parcels have no schema shows up as a real bug class. In any app you have decompiled, find
a `Parcelable`:

```bash
# host
grep -rn -A30 "public void writeToParcel" out/sources/ | head -60
grep -rn -A30 "CREATOR" out/sources/ | head -60
```

For each one, count the fields written by `writeToParcel` and the fields read by the `CREATOR`'s
`createFromParcel`. **They must match exactly, in order and in count.**

An asymmetry means:

- If the reader reads **fewer** fields, the trailing bytes stay in the parcel. If that object is then
  re-serialised, everything after it shifts. This is the mechanism behind the `Bundle`
  re-serialisation bug class.
- If the reader reads **more**, it consumes the *next* object's bytes, and every subsequent field is
  attacker-influenced.

Either is a security bug when the parcel crosses a privilege boundary.

---

## Task 10 — Answer these without looking

1. Write out the `String16` wire format for the string `"hi"`, in hex.
2. Write out the wire format for `null` and for `""`. Why is the difference dangerous?
3. What are the four fields of an interface token, in order?
4. What is `0x53595354` and why is it there?
5. What is in the offsets array, and what would happen without it?
6. `flags = 0x113` on a `flat_binder_object`. Decompose it.
7. Exception code `−1` — what is it, and what two int32s may follow the message?
8. What is the difference between `service call` hex output and `binder-probe` hex output, and what
   goes wrong if you confuse them?
9. Give the exact message a token mismatch produces on Android 11.
10. Why can the token not serve as authentication?

---

## Success criteria

- [ ] You decoded a 64-byte parcel by hand and the arithmetic closed exactly.
- [ ] You can write the `String16` format, including the null and empty cases, from memory.
- [ ] You identified an embedded `flat_binder_object` in a hex dump and decomposed its flags.
- [ ] You verified the stack-trace header-size arithmetic on a real refusal.
- [ ] `binder-probe.c` compiled with no warnings and ran on your device.
- [ ] You produced *both* refusal messages — the identity one and the token one — and can explain
      which control produced each.

---

## Going further

- Feed `parcel-decode.py` a parcel with a deliberately wrong `--layout` and watch it fail. That
  failure is the *only* signal a schema-less format gives you.
- Use `service call <svc> <code> s16 <string>` to add arguments, and capture the request with
  `../scripts/trace-binder-transactions.js` running in the target. Compare what you sent with what
  arrived.
- Read `Parcel::writeInterfaceToken` in `frameworks/native/libs/binder/Parcel.cpp` and check that its
  four writes match the four fields you decoded in Task 3.

---

## Next

[Lab 03 — The identity boundary](lab-03-identity-boundary.md) — prove the UID stamp cannot be
forged, then exploit and fix all four `clearCallingIdentity` misuse patterns.
