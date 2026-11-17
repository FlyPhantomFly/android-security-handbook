# Lab 01 — Reading `/proc/<pid>/maps` by hand, and finding a known value in a live process

> **Objective:** be able to open a process's address space, say what every line means, compute a
> runtime address from a static one, and locate a value you planted — without any tool doing the
> thinking for you.

**Difficulty:** beginner to intermediate
**Time:** 60–90 minutes
**Prerequisites:** [02-Linux-Basics](../../02-Linux-Basics/README.md) for `adb shell` and file
redirection; [15-Native-Code](../../15-Native-Code/README.md) §3 for what a PT_LOAD segment is.
Chapter 19 §2 and §3.1–3.7 are the reading this lab exercises.

**What you need**

| | |
|---|---|
| A device or emulator | Android 8 or newer, arm64 preferred. Root is **not** required. |
| `adb` | On your PATH. |
| The NDK | To build the fixtures. Or skip to Part 4 and use the shipped capture. |
| Python 3 | For [`../scripts/maps-analyse.py`](../scripts/maps-analyse.py). |

---

## 0. Why this lab is first

Every dynamic technique in this repository — Frida hooking, Ghidra address rebasing, DEX carving,
heap inspection — rests on one file. `Process.enumerateRanges()` is a parse of it.
`Module.findBaseAddress()` is a lookup in it. `Memory.scan` searches the regions it lists. The
in-memory DEX sweep in [40-Obfuscation](../../40-Obfuscation/README.md) enumerates it.

If you cannot read it unaided you will be permanently dependent on tools agreeing with each other,
and you will have no way to tell which one is wrong when they do not.

> **Warning — an important limitation you will hit in Part 1**
> On a stock Android 13 device, an ordinary `adb shell` **cannot** read another app's maps:
>
> ```
> $ adb shell head -3 /proc/$(pidof zygote64)/maps
> head: /proc/541/maps: Permission denied
> ```
>
> That is SELinux, not a mistake on your part. Parts 1–3 use processes you own, which works
> everywhere. Part 4 uses a supplied capture. Part 5 shows the route into a real app, which needs
> Frida.

---

## Part 1 — The anatomy of one line

### Step 1.1 Capture your own shell's map

```bash
# adb shell
cat /proc/self/maps | head -20
```

You will see lines shaped like this. This one is real, from an Android 13 arm64 device:

```
7bd3e7e000-7bd3ebb000 r--p 00000000 fc:04 618      /apex/com.android.runtime/lib64/bionic/libc.so
```

### Step 1.2 Name every field

Write out what each of the six fields is, then check yourself against the table.

| Field | Value above | What it is |
|---|---|---|
| Address range | `7bd3e7e000-7bd3ebb000` | Start (inclusive) and end (**exclusive**) virtual addresses, hex, no `0x`. |
| Permissions | `r--p` | Read, write, execute, then `p` for MAP_PRIVATE or `s` for MAP_SHARED. |
| File offset | `00000000` | How far into the backing file this mapping starts. |
| Device | `fc:04` | Major:minor of the device holding the file. `00:00` means no file. |
| Inode | `618` | The file's inode. `0` means no file. |
| Path | `/apex/…/libc.so` | The backing file, a `[bracketed]` special region, or nothing. |

**Compute the size.** `0x7bd3ebb000 - 0x7bd3e7e000 = 0x3d000` = 249856 bytes = 244 KiB.

```bash
# adb shell
printf '%d\n' $((0x7bd3ebb000 - 0x7bd3e7e000))
```

> **Definition — page**
> The smallest unit of memory the hardware can protect or map independently. On almost every
> Android device it is 4096 bytes; since Android 15 some devices use 16384. Every address in the
> maps file is a multiple of the page size, because the kernel cannot describe anything finer.
> Ask the device rather than assuming: `getconf PAGESIZE`.

### Step 1.3 Verify that everything is page-aligned

```bash
# adb shell
cat /proc/self/maps | cut -d- -f1 | grep -v '000$' | head
```

Expect no output. Every start address ends in three hex zeros, which is `& 0xfff == 0`, which is
4096-aligned.

**Question 1.** On a 16 KiB-page device, how many trailing hex zeros would you expect, and why is
"three zeros" not a sufficient test there?

<details><summary>Answer</summary>

16384 is `0x4000`. An address that is a multiple of `0x4000` still ends in three hex zeros, but the
fourth-from-last digit must be `0`, `4`, `8` or `c`. So "three zeros" passes on both, and is
a weaker test on a 16 KiB device. The reliable check is `addr % pagesize == 0` with the page size read
from `getconf PAGESIZE`. `maps-analyse.py` infers it from the greatest common divisor of every
boundary, which gets it right on both without being told.

</details>

---

## Part 2 — Why one library appears four times

### Step 2.1 Look at a single library's segments

```bash
# adb shell
grep 'libc.so' /proc/self/maps
```

Real output:

```
7bd3e7e000-7bd3ebb000 r--p 00000000 fc:04 618   /apex/com.android.runtime/lib64/bionic/libc.so
7bd3ebb000-7bd3f4c000 r-xp 0003d000 fc:04 618   /apex/com.android.runtime/lib64/bionic/libc.so
7bd3f4c000-7bd3f50000 r--p 000ce000 fc:04 618   /apex/com.android.runtime/lib64/bionic/libc.so
7bd3f50000-7bd3f52000 rw-p 000d1000 fc:04 618   /apex/com.android.runtime/lib64/bionic/libc.so
```

Four lines, one file, one inode (`618`), four different permission sets.

### Step 2.2 Read the pattern

| Line | Permissions | File offset | What lives here |
|---|---|---|---|
| 1 | `r--p` | `0x00000` | ELF header, program headers, `.dynsym`, `.dynstr`, `.rodata` — read-only data |
| 2 | `r-xp` | `0x3d000` | `.text` — the actual instructions. Readable and executable, **not** writable |
| 3 | `r--p` | `0xce000` | The RELRO region: `.got`, `.init_array`. Writable during relocation, then locked |
| 4 | `rw-p` | `0xd1000` | `.data` and `.bss` — writable globals |

Three things follow, and each answers a question people ask repeatedly.

1. **The file offsets are consecutive and ascending, and they match the gaps.** `0x3d000 - 0 =
   0x3d000`, and line 1 spans `0x3d000` bytes. The mapping is a faithful, contiguous image of the
   file, split only so that different parts get different permissions.
2. **Nothing is both `w` and `x`.** That is W^X, enforced by the page tables. It is why writing
   shellcode into a buffer and jumping to it stopped working in about 2005.
3. **The load base is the first line's start.** `0x7bd3e7e000`, the lowest mapping whose file
   offset is `00000000`.

> **Mental Model**
> A shared library on disk is one file. In memory it is a small terrace of mappings that share a
> wall, cut where the permissions need to change. "Why does maps list libc three times?" has the
> same answer as "why does a house have more than one room".

### Step 2.3 Compute a runtime address from a static one

This is the single most-used calculation in dynamic analysis.

```bash
# host — get a static address for a function inside libc
adb pull /apex/com.android.runtime/lib64/bionic/libc.so .
python3 ../../15-Native-Code/scripts/elf-inspect.py libc.so --dynsyms | grep -w ' malloc'
```

Then:

```
runtime address  =  load base  +  static address
```

Check it against what the process itself thinks:

```bash
# adb shell
/data/local/tmp/ch19/mem-landmarks landmarks -v
```

**Question 2.** Suppose you used line 2's start (`0x7bd3ebb000`) as the load base by mistake,
because it is the one with the code in it. By how much would every computed address be wrong, and
would the error be obvious?

<details><summary>Answer</summary>

Wrong by `0x3d000` = 249856 bytes, low by exactly the size of the first segment. It would not be
obvious. Every address would still land inside libc, in a plausible-looking region, and a hook set
there would attach successfully to the wrong instruction. You would get a crash or silence, not an
error message. This is why `maps-analyse.py` takes the lowest mapping **at file offset 0** and
prints a `?` when it cannot find one.

</details>

---

## Part 3 — Build the fixtures and read your own address space

### Step 3.1 Build

```bash
# host, from 19-Memory/examples/
export ANDROID_HOME="$HOME/Android/Sdk"
./build-memory-fixtures.sh /tmp/ch19
adb shell mkdir -p /data/local/tmp/ch19
adb push /tmp/ch19/. /data/local/tmp/ch19/
adb shell chmod 755 /data/local/tmp/ch19/heap-bugs /data/local/tmp/ch19/mem-landmarks
```

> **Warning — two things that will waste your time**
> **Git Bash mangles absolute paths in `adb push`.** `adb push x /data/local/tmp/` becomes
> `C:/Program Files/Git/data/local/tmp/` and fails with `secure_mkdirs failed`. Prefix the command
> with `MSYS_NO_PATHCONV=1`, or use PowerShell or `cmd`.
>
> **Some devices refuse to `exec` from `/data/local/tmp`.** You get
> `./heap-bugs: No such device or address`. Run it through the loader instead, with an absolute
> path:
>
> ```bash
> # adb shell
> /system/bin/linker64 /data/local/tmp/ch19/mem-landmarks landmarks
> ```

### Step 3.2 Read the landmarks

```bash
# adb shell
/data/local/tmp/ch19/mem-landmarks landmarks -v
```

Real output from an Android 13 arm64 device:

```
pid=16168 exe=7bd5393000 libc=7bd3e7e000 linker=7bd64d6000 stack=7fe7abb000 heap=7a03e82000 page=4096

  the mapping holding a fresh malloc(64) at 0xb400007a03e829c0:
    7a03e82000-7a03ec2000 rw-p 00000000 00:00 0     [anon:scudo:primary]
```

Three things to notice, and all three matter later.

1. **`[anon:scudo:primary]`.** The native heap is not `[heap]`. `[heap]` is the old `brk` region,
   which bionic barely uses. The real heap is a set of *named anonymous* mappings, labelled by the
   allocator itself with `prctl(PR_SET_VMA_ANON_NAME)`. The name tells you which allocator you are
   looking at, which is how `maps-analyse.py` fingerprints it.
2. **The pointer is `0xb400007a03e829c0` but the mapping starts at `0x7a03e82000`.** The top byte,
   `0xb4`, is a **tag**, not part of the address. Strip it before comparing anything.
3. **`stack=7fe7abb000` is nowhere near the others.** Stack, heap and libraries are randomised
   independently.

> **Under the Hood — the `0xb4`**
> Since Android 11, 64-bit processes get a tag in the top byte of every heap pointer, on hardware
> and kernels that support Arm's Top-Byte-Ignore. The constant is `POINTER_TAG` in
> `bionic/libc/bionic/malloc_tagged_pointers.h`, and its value is `0xB4`. The hardware ignores the
> byte when dereferencing, so the program works; `/proc/<pid>/maps` prints untagged addresses, so
> naive comparisons fail. `heap-bugs.c`'s `untag()` is four lines and exists entirely because of
> this.

### Step 3.3 Prove the tag is not part of the address

```bash
# adb shell
/data/local/tmp/ch19/heap-bugs layout | head -25
```

Look for:

```
  small[0]  0xb400007cbeeee2e0  tagged; searching maps for 007cbeeee2e0
  small[0]  0xb400007cbeeee2e0  in 007cbeeee000-007cbef2e000 rw-p [anon:scudo:primary]
```

The first attempt with the raw value would have matched no region. That is the bug most people
write on their first day.

**Question 3.** A colleague's script computes `Module.findBaseAddress('libfoo.so')` and subtracts it
from a `malloc` return value to get "an offset into libfoo". The number comes out around 12
quintillion. What has gone wrong, and is the fix to mask the pointer?

<details><summary>Answer</summary>

Two things, and only one is the tag. The tag makes the value enormous — `0xb4` in the top byte is
about 1.3 × 10^19. But the deeper error is conceptual: a `malloc` return value is not inside
`libfoo.so` at all. It is in the heap. Masking the tag would produce a smaller, equally meaningless
number. The fix is to notice that subtracting a module base only means something for an address
inside that module, which `Process.findModuleByAddress()` will tell you.

</details>

### Step 3.4 Run the analyser on your own capture

```bash
# host
adb shell "cat /proc/self/maps" > my-maps.txt
python3 ../scripts/maps-analyse.py my-maps.txt
```

Read the four blocks it prints — SUMMARY, ALLOCATOR AND CHECKER, MODULES, FINDINGS — and check each
number against the raw file by hand at least once. In particular:

- **`address space reserved` will be enormous** — around 10 GiB for a trivial shell process. That is
  reserved *address space*, not memory. Most of it is never touched. `--smaps` gives the real
  numbers.
- **`page size (inferred) 4096`** — an inference from the boundaries, and the analyser says so.

---

## Part 4 — Triage a capture you did not make

The shipped fixture [`../examples/fixture-app-maps.txt`](../examples/fixture-app-maps.txt) is a
synthetic but structurally faithful app-process capture, with a handful of things deliberately
planted in it. Its header says exactly what it is and is not; read it before you use it.

```bash
# host
python3 ../scripts/maps-analyse.py ../examples/fixture-app-maps.txt
```

### Step 4.1 Before reading the output, find them yourself

Answer these with `grep` alone.

1. Which mappings are writable **and** executable?
2. Which mapped files have been **deleted** from disk?
3. Which executable code came from a file that never existed on any filesystem?
4. Which system library has a segment you can execute but not read?
5. Which single mapping is `MAP_SHARED` and writable?

<details><summary>The greps</summary>

```bash
grep ' rwx' ../examples/fixture-app-maps.txt
grep '(deleted)' ../examples/fixture-app-maps.txt
grep '/memfd:' ../examples/fixture-app-maps.txt
grep -- '--xp' ../examples/fixture-app-maps.txt
grep ' rw-s ' ../examples/fixture-app-maps.txt
```

</details>

### Step 4.2 Now compare with the tool

```bash
python3 ../scripts/maps-analyse.py ../examples/fixture-app-maps.txt | sed -n '/FINDINGS/,$p'
```

It reports 13 findings across six tags: `RWX`, `ANON-EXEC`, `DELETED`, `DATA-EXEC`, `MEMFD-EXEC`,
`SHARED-RW`, `XOM`.

### Step 4.3 The judgement, which is the actual lab

Two of the `RWX` hits look identical to `grep`:

```
0071c4000000-0071c4100000 rwxp 1.0 MiB   [anon:dalvik-jit-code-cache]
007360000000-007360004000 rwxp 16.0 KiB  (anonymous)
```

Write one sentence about each, of the form *"this is X, and it is / is not worth pursuing because
Y"*.

<details><summary>Model answers</summary>

**The first** is ART's JIT code cache. It is writable and executable because a JIT compiler must
write instructions and then run them, and every Android device that has ever shipped has one. It is
not worth pursuing as a finding. It *is* worth knowing about, because an anti-tamper check that
counts RWX regions will find it, and because code injected into it is code that no static analysis
of the APK will ever show.

**The second** is a 16 KiB unnamed RWX anonymous mapping. Nothing named it, so nothing in bionic or
ART created it through the usual paths. That does not make it malicious — an app can `mmap` RWX
memory for entirely legitimate reasons — but it is unexplained, and unexplained executable memory is
exactly the thing to explain. The next step is to find out who created it (hook `mmap` and
`mprotect`) and what is in it (`hexdump` the first bytes and look for an ELF header or ARM64
prologues), not to write "RWX region found" in a report.

</details>

**Question 4.** The analyser flags four `DATA-EXEC` regions, one of which is
`.../lib/arm64/libnative-lib.so` — the app's own bundled native library. Why is the tool right to
flag it and wrong to be alarmed by it?

<details><summary>Answer</summary>

Right to flag it, because "executable code loaded from writable storage" is a real category and the
tool cannot tell the members apart. Wrong to be alarmed, because that is where every app's own
native libraries live: the installer extracts them from the APK to `/data/app/<pkg>/lib/<abi>/`, and
that directory is not writable by the app at run time. The distinction that matters is whether the
file was written at **install** time or at **run** time. `libdyn-payload.so` under
`/data/data/<pkg>/files/` is the second kind, and that is the one to chase.

</details>

---

## Part 5 — Finding a known value in a live process

The point of everything above.

### Step 5.1 Plant a value and find it, with no tooling

`heap-bugs uaf` writes a known string into a heap block and prints the address:

```bash
# adb shell
/data/local/tmp/ch19/heap-bugs uaf
```

```
  allocated 0xb400007369a46650 and filled it with a fake secret
  contents  53 45 53 53 49 4f 4e 3d 64 65 61 64 62 65 65 66 63 61 66 65 62 61 62 65
```

Those bytes are `SESSION=deadbeefcafebabe`. You have the address and the contents, and you know from
Part 3 which region it lands in.

**Do this by hand:**

1. Strip the tag: `0xb400007369a46650` becomes `0x7369a46650`.
2. Find the region containing it, in the same run's `layout` output.
3. Confirm it is `[anon:scudo:primary]` and not the ART heap, not the stack, not a module.

### Step 5.2 Now do it in a process you do not control

You cannot `cat` another app's maps. You can run inside it.

```bash
# host
frida -U -n com.example.target -l ../scripts/mem-search.js
```

```javascript
// Frida REPL
rpc.exports.regions()             // what a scan would actually cover, and what it skips
rpc.exports.text('Bearer ')       // ASCII
rpc.exports.utf16('Bearer ')      // the same string as a Java String would store it
```

Take one hit and explain it:

```javascript
rpc.exports.where('0x7311223344')
rpc.exports.context('0x7311223344', 128)
```

> **Pentester's Note**
> `utf16()` exists because the ASCII search misses Java `String`s outright — every character has a
> zero byte after it. Since Android 6 ART also compresses Latin-1 strings to one byte per character,
> so sometimes the ASCII search *does* hit. Try both, always. "We could not find the token in
> memory" after searching one encoding is not a result.

### Step 5.3 Turn a hit into a finding

A secret being in memory while the app is using it is not a vulnerability. Use the two-call test:

```javascript
rpc.exports.scrubTest('the-token-value')   // baseline, while it is in use
// now log out in the app
rpc.exports.scrubTest('the-token-value')   // after
```

The count staying the same is the finding. The count being non-zero the first time is not.

**Question 5.** The count drops from 6 to 2. Is that a pass or a fail, and what do you write?

<details><summary>Answer</summary>

Neither, on its own. Four owners disposed of their copy and two did not, so the app has a scrubbing
discipline that is applied inconsistently. Write it as: the token remains resident in two locations
after logout; identify them with `where()`; state whether they are native (fixable with an explicit
scrub) or Java `String`s (not fixable without changing the type to `char[]` or `byte[]`, because a
`String` is immutable and interned — see [13-ART](../../13-ART/README.md)). Then state the severity
honestly: this matters if heap dumps leave the device or the device is rooted, and is informational
otherwise.

</details>

---

## Success criteria

You are done when you can, without notes:

- [ ] Name all six fields of a maps line and compute a region's size from it.
- [ ] Explain why one library occupies four lines, and what each permission set holds.
- [ ] Identify a load base correctly, and say what goes wrong if you pick the wrong line.
- [ ] Recognise a tagged heap pointer on sight and strip the tag.
- [ ] Say which allocator a process is using, from the `[anon:…]` names alone.
- [ ] Distinguish an expected RWX region from an unexplained one, and say what the next step is.
- [ ] Explain why `adb shell` cannot read an app's maps, and what does work instead.
- [ ] State why finding a secret in memory is usually not a finding, and what makes it one.

---

## Where to go next

| If you want to | Go to |
|---|---|
| Understand what the allocator is doing between those addresses | [Lab 02](lab-02-allocator-behaviour.md) |
| See a memory-safety bug actually get caught | [Lab 03](lab-03-detection-hwasan-mte.md) |
| Test yourself | [Lab 04 — CTF](lab-04-ctf-the-quiet-corruption.md) |
| Hook the code that writes into these regions | [53-Frida](../../53-Frida/README.md) |
| Rebase a static address for a decompiler | [57-Ghidra](../../57-Ghidra/README.md) |
| Understand the ELF that produced those four segments | [15-Native-Code](../../15-Native-Code/README.md) |
