# Lab 02 — The allocator, measured: Scudo, size classes, reuse, and ASLR entropy

> **Objective:** stop believing what blog posts say about heap layout and measure it on the device
> in front of you — where allocations land, how far apart they are, whether a freed block comes
> straight back, and how much of the address space is actually randomised.

**Difficulty:** intermediate
**Time:** 90–120 minutes
**Prerequisites:** [Lab 01](lab-01-reading-proc-maps.md). Chapter 19 §3.6–3.10 is the reading.

**What you need**

| | |
|---|---|
| A device or emulator | Android 11 or newer to see Scudo; Android 8–10 to see the older allocator. Root not required. |
| The fixtures | Built and pushed as in Lab 01 Part 3. |
| Python 3 and `awk` | On the device's shell, `toybox awk` is present on Android 9+. |

---

## 0. Why measure rather than read

Chapter 15 says, and cites this chapter for it: *"Scudo since Android 11, jemalloc before. Heap
layout, and therefore heap-grooming technique, differs by version."* That is true and it is not
enough. Within "Scudo", behaviour still depends on:

- whether the device is configured as low-RAM (AOSP documents that low-memory devices kept jemalloc
  when Scudo became the default),
- whether the app enabled GWP-ASan,
- whether the process is 32-bit or 64-bit,
- what the OEM set in `SCUDO_OPTIONS`,
- whether the app targets API 30 or higher, which decides whether pointers are tagged.

None of that is knowable from a version number. All of it is measurable in five minutes.

> **🔍 Pentester's Note**
> The deliverable from this lab is not "the heap is groomable". It is a table of measured distances
> for the size classes the target app actually uses. That table is what turns "there is an overflow"
> into "there is an overflow that reaches *this*", and it is the difference between an accepted
> finding and a rejected one.

---

## Part 1 — Where things land

### Step 1.1 The baseline run

```bash
# adb shell
/data/local/tmp/ch19/heap-bugs layout
```

Real output, Android 13, arm64, non-low-RAM device:

```
Eight 32-byte allocations, in order:
  [0] 0xb400007337882060
  [1] 0xb4000073378829a0   delta from previous: +2304 bytes
  [2] 0xb400007337882670   delta from previous: -816 bytes
  [3] 0xb4000073378824c0   delta from previous: -432 bytes
  [4] 0xb4000073378828e0   delta from previous: +1056 bytes
  [5] 0xb400007337882100   delta from previous: -2016 bytes
  [6] 0xb4000073378820d0   delta from previous: -48 bytes
  [7] 0xb4000073378823a0   delta from previous: +720 bytes
```

### Step 1.2 Read what the deltas say

Three separate facts are visible in those eight lines.

**The deltas are not monotonic.** Allocation `[2]` is at a *lower* address than `[1]`. A naive
free-list allocator hands out addresses in a predictable order; this one does not. Scudo randomises
the order in which it hands out blocks within a region, deliberately, precisely to make grooming
harder.

**The deltas are all multiples of 48.** `2304 = 48 × 48`, `816 = 48 × 17`, `432 = 48 × 9`,
`48 = 48 × 1`. A 32-byte request occupies a 48-byte slot: 32 bytes of payload plus a 16-byte chunk
header. That 48 is the **stride** for this size class, and it is the number that matters.

**They are all inside one region.** Every address begins `0xb4000073378…`, and Lab 01 showed the
containing region is `[anon:scudo:primary]`.

### Step 1.3 Confirm the stride independently

Run it several times and collect the minimum absolute delta:

```bash
# adb shell
for i in 1 2 3 4 5 6 7 8 9 10; do
  /data/local/tmp/ch19/heap-bugs layout
done | grep 'delta from previous' | tr -d '+' |
  awk '{ d = $NF < 0 ? -$NF : $NF; if (d > 0 && (min == 0 || d < min)) min = d } END { print "minimum stride:", min }'
```

**Question 1.** You measure the minimum stride as 48 for a 32-byte request. An overflow writes 20
bytes past the end of a 32-byte block. Does it reach the next block's payload?

<details><summary>Answer</summary>

No — but only just, and only sometimes. Sixteen of those 20 bytes land in the next chunk's header;
the remaining four land in its payload. So the answer is "it reaches the next payload by 4 bytes,
after destroying a chunk header on the way". Destroying the header is significant on its own: Scudo
checksums it, so the corruption is detected the moment that chunk is freed — which is why
`heap-bugs invfree` aborts with `Scudo ERROR: corrupted chunk header`. An attacker wanting the
payload without the abort has to overflow *past* a chunk they never cause to be freed, or into a
block from a size class with less header in the way.

Note what this reasoning needs: the measured stride, the header size, and the knowledge that the
header is checksummed. None of the three is guessable.

</details>

### Step 1.4 The size-class boundary

From the same run:

```
  malloc(32)        0xb400007337882060
  malloc(65536)     0xb4000075178a9030   delta: +8053223312
  malloc(4194304)   0xb40000729587f000   delta: -2717921440
```

and the regions:

```
  64 KiB   in 007517889000-0075178c9000 rw-p [anon:scudo:primary]
  4 MiB    in 00729587e000-007295c7f000 rw-p [anon:scudo:secondary]
```

The 64 KiB allocation is still in the **primary**. The 4 MiB one is in the **secondary**. Somewhere
between them is the threshold at which Scudo stops carving from its own pools and asks the kernel
for a dedicated mapping.

Find it:

```bash
# adb shell — bisect the threshold with the Frida probe, or by hand:
/data/local/tmp/ch19/heap-bugs layout | grep -E 'scudo:(primary|secondary)'
```

Better, use the Frida ladder, which does the whole sweep in one call:

```bash
# host
frida -U -n com.example.target -l ../scripts/malloc-trace.js
```

```javascript
rpc.exports.probe()
```

That prints a size ladder from 8 bytes to 4 MiB with the region each landed in.

> **🧠 Mental Model — primary and secondary**
> The primary is a set of pre-reserved regions, one per size class, from which small blocks are
> carved with almost no work. The secondary is "just call `mmap`". Small allocations are fast and
> crowded together; large ones are slower, individually mapped, and usually flanked by guard pages.
> An overflow of a large allocation is far more likely to fault immediately, and far less likely to
> be useful, than an overflow of a small one. That asymmetry is why grooming targets small objects.

**Question 2.** Why does the *secondary* being guarded make an overflow there less useful to an
attacker, even though the bug is identical?

<details><summary>Answer</summary>

Because usefulness comes from writing into something else you care about. A secondary allocation
sits in its own mapping with unmapped or `PROT_NONE` pages on either side, so a linear overflow runs
into nothing but a fault. There is no adjacent object to corrupt. The bug is just as real and just
as much a defect; its exploitation primitive is far weaker. That distinction — same bug, different
reachability — is exactly what a severity rating should be tracking, and
`examples/mem-landmarks.c guard` demonstrates the mechanism directly.

</details>

---

## Part 2 — Does a freed block come straight back?

### Step 2.1 Measure it

```bash
# adb shell
/data/local/tmp/ch19/heap-bugs layout | grep -A1 'Free small'
```

Real output:

```
Free small[3] (0xb4000073378824c0), then malloc(32) again:
  new allocation: 0xb4000073378824c0  SAME ADDRESS (immediate reuse)
```

**Same address, immediately.** The textbook answer — "Scudo has a quarantine, so you will not get it
back" — is wrong on this device, because Android ships Scudo with the quarantine size set to zero by
default. `QuarantineSizeKb` is a real Scudo option with a documented non-zero default in upstream
Scudo, and Android chose the memory over the mitigation.

### Step 2.2 See what that means for a use-after-free

```bash
# adb shell
/data/local/tmp/ch19/heap-bugs uaf
```

The important four lines:

```
  malloc(64) again -> 0xb400007369a46650 == the freed block. The hole has been reclaimed.
  writing through the dangling pointer:
  wrote 0x41 to 0xb400007369a46650
  other[0..15]   41 77 77 77 77 77 77 77 77 77 77 77 77 77 77 77
```

`other` was filled with `0x77`. Its first byte is now `0x41`, written through a pointer whose owner
believed it still owned that memory. Two objects, one address, and no diagnostic of any kind.

> **⚠️ Warning**
> Read the last sentence again. The stock build printed nothing, returned zero, and carried on. This
> is the normal case: a use-after-free on a stock Android device is **silent**. That silence is why
> Lab 03 exists.

### Step 2.3 Turn the quarantine on and re-measure

```bash
# adb shell
SCUDO_OPTIONS=QuarantineSizeKb=256:ThreadLocalQuarantineSizeKb=64 \
  /data/local/tmp/ch19/heap-bugs layout | grep -A1 'Free small'
```

Compare. If the address changes, you have just demonstrated a mitigation that exists, is
configurable, is off, and costs memory to turn on. That is a legitimate thing to say to a client who
controls their own device fleet, and a pointless thing to say to one who does not.

**Question 3.** Your report recommends "enable the Scudo quarantine". The developer replies that
they cannot — it is a platform setting, not an app setting. Are they right, and what should the
recommendation have been?

<details><summary>Answer</summary>

Largely right. `SCUDO_OPTIONS` is an environment variable read at process start, and an ordinary app
does not control its own environment; the Zygote does. An app *can* influence allocator behaviour
through the manifest — `android:gwpAsanMode="always"` turns on GWP-ASan, and `android:memtagMode`
turns on MTE where the hardware supports it — but not through Scudo options.

The recommendation should have been the fix rather than the mitigation: eliminate the use-after-free
(ownership discipline, as in `heap-bugs-fixed.c`), and run HWASan in CI so the next one is caught
before it ships. Recommending a control the developer cannot apply is how a report loses its
audience.

</details>

---

## Part 3 — The 32-bit difference

```bash
# adb shell — only if the device still supports 32-bit
/system/bin/linker /data/local/tmp/ch19/heap-bugs-arm32 layout | head -14
```

Real output:

```
  [0] 0xef440970
  [1] 0xef4402b0   delta from previous: -1728 bytes
  ...
  small[0]  0xef440970  in 0000ef3c0000-0000ef480000 rw-p [anon:scudo:primary]
```

Two differences from the 64-bit run, and both are security-relevant.

| | 64-bit | 32-bit |
|---|---|---|
| Pointer tag | `0xb4` in the top byte | **none** — there is no spare byte |
| HWASan | available | **not available** |
| MTE | available on Armv9 hardware | **not available** |
| ASLR entropy | large | much smaller; a 32-bit address space has far fewer places to hide |

**Question 4.** An app ships both `arm64-v8a` and `armeabi-v7a`. On a 64-bit device, which one runs,
and why does the answer matter for this table?

<details><summary>Answer</summary>

The 64-bit one, if the APK contains it and the device is 64-bit: the package manager picks the
"best" ABI and extracts only that. So on a modern device the 32-bit library is dead weight and the
table's right-hand column does not apply.

It matters in two cases. First, a 32-bit-only device (or a 32-bit-only app) genuinely gets the
weaker column. Second — and this is the one people miss — an app that ships *only* `armeabi-v7a`
runs 32-bit even on a 64-bit device, and therefore has no pointer tagging, no HWASan and no MTE
available to it at all. Checking which ABIs are in the APK is a one-line
`unzip -l base.apk | grep lib/` and it changes what you can say about the whole native surface.

</details>

---

## Part 4 — ASLR, measured properly

### Step 4.1 Entropy for an exec'd process

```bash
# adb shell
for i in $(seq 1 50); do
  /data/local/tmp/ch19/mem-landmarks landmarks
done | tr ' ' '\n' | grep '^libc=' | sort -u | wc -l
```

Fifty distinct values means libc lands somewhere different on every `exec`.

Measure the *range* too, not just the count:

```bash
# adb shell
for i in $(seq 1 50); do
  /data/local/tmp/ch19/mem-landmarks landmarks
done | tr ' ' '\n' | grep '^libc=' | cut -d= -f2 |
  awk '{ v = strtonum("0x" $1); if (min=="" || v<min) min=v; if (v>max) max=v }
       END { printf "min=%x max=%x span=%d bytes (~2^%.1f)\n", min, max, max-min, log(max-min)/log(2) }'
```

### Step 4.2 The part that matters, and that you cannot measure this way

Everything in Step 4.1 is about a process the kernel `exec`s. **An Android app is not one.**

An app process is created by `fork()` from the Zygote, with no `exec()`. The child inherits the
parent's page tables. Every library the Zygote had loaded — `libart.so`, `libc.so`, the boot image,
the whole framework — is at **exactly the same address in every app on the device**, and stays there
until the Zygote restarts, which in practice means until reboot.

> **⚠️ Warning — the ASLR consequence, stated plainly**
> ASLR randomises per-`exec`. Android apps do not `exec`. Therefore for the inherited portion of an
> app's address space there is effectively **one** layout per boot, shared by every app.
>
> Two consequences follow:
> 1. An address leak from *any* app on the device discloses the framework layout for *every* app on
>    that device, until reboot.
> 2. An attacker who can run their own app can read their own maps to learn the layout of the
>    inherited libraries in a target app, without attacking the target at all.
>
> This is a well-known and documented weakening of ASLR on Android, and it is the reason "ASLR is
> enabled" is not a complete answer to "is this address predictable". Chapter 06 and Chapter 21
> cover why the Zygote works this way — the copy-on-write sharing is what makes app startup fast.
> This chapter's job is to say what it costs.

### Step 4.3 Observe the inherited-layout effect for yourself

You cannot read another app's maps from `adb shell`. You can compare two processes you own, which
are both `exec`'d and therefore *should* differ:

```bash
# adb shell
/data/local/tmp/ch19/mem-landmarks landmarks
/data/local/tmp/ch19/mem-landmarks landmarks
```

Different libc bases. Now, with Frida, compare two **app** processes:

```bash
# host — attach to two different apps in turn
frida -U -n com.example.appone -l ../scripts/enumerate-ranges.js -o one.txt
frida -U -n com.example.apptwo -l ../scripts/enumerate-ranges.js -o two.txt
```

```javascript
rpc.exports.find('libart.so')
```

in each, and compare the load bases.

**Question 5.** Suppose the two apps report the *same* `libart.so` base. Is that a vulnerability?

<details><summary>Answer</summary>

No. It is a documented architectural consequence of the Zygote model, present on every Android
device, and not something either app did wrong. Reporting it as a finding against an app is a
category error.

It is, however, a fact you must use correctly *elsewhere*. When you assess whether some *other* bug
is exploitable, "the attacker needs an information leak to defeat ASLR" is a much weaker
counter-argument on Android than on a desktop, because the leak may be obtainable from a different
process entirely. Say that in the exploitability analysis, not in the findings list.

</details>

### Step 4.4 What is still randomised per app

Not everything is inherited. Anything mapped *after* the fork is fresh:

- the app's own APK, its `base.odex`, and its bundled `.so` files,
- the ART heap regions allocated after the fork,
- Scudo's regions for the child,
- thread stacks created after the fork.

```javascript
// Frida REPL, in each of two apps
rpc.exports.find('libnative-lib')
```

Different bases. So the practical picture is *mixed*: framework libraries predictable across apps
and across time, app-specific mappings randomised. An exploit that only needs a framework gadget is
in a much better position than one that needs an app-specific address.

---

## Part 5 — Build the table you will actually put in a report

Fill this in for your target, measured rather than assumed.

| Question | How you measured it | Your answer |
|---|---|---|
| Which allocator? | `maps-analyse.py` ALLOCATOR block, or `[anon:]` names | |
| Are pointers tagged? | top byte of a `malloc` return in `heap-bugs layout` | |
| Stride for the size class the bug touches | `neighbours(N)` in `malloc-trace.js` | |
| Header size in front of a block | stride minus request size | |
| Immediate reuse after free? | `probe()` reuse test, or `heap-bugs layout` | |
| Primary/secondary threshold | `probe()` ladder, region name change | |
| Is GWP-ASan on? | `[anon:GWP-ASan …]` present in maps | |
| Is the process 32- or 64-bit? | `Process.pointerSize`, or the ABI in the APK | |
| Framework libraries shared across apps? | compare `libart.so` base in two apps | |

**Every row is a measurement with a command next to it.** That is what makes the resulting
exploitability paragraph defensible.

---

## Success criteria

- [ ] You can state the stride for a given request size on your device, and where the number came
      from.
- [ ] You can explain why the allocation order is non-monotonic and what that costs an attacker.
- [ ] You can demonstrate immediate reuse after `free()`, and say why the "quarantine" answer is
      wrong here.
- [ ] You can locate the primary/secondary threshold and explain why it changes exploitability.
- [ ] You can list four ways a 32-bit process is worse off, without looking.
- [ ] You can explain the Zygote ASLR consequence in one paragraph, including what it does *not*
      mean.
- [ ] You can say which parts of an app's address space are inherited and which are fresh.

---

## Where to go next

| If you want to | Go to |
|---|---|
| Watch a bug actually be caught | [Lab 03](lab-03-detection-hwasan-mte.md) |
| Test yourself | [Lab 04 — CTF](lab-04-ctf-the-quiet-corruption.md) |
| Read the addresses you measured, by hand | [Lab 01](lab-01-reading-proc-maps.md) |
| Understand the Zygote itself | [06-Android-Architecture](../../06-Android-Architecture/README.md) |
| Understand the sandbox the fork lands in | [21-App-Sandbox](../../21-App-Sandbox/README.md) |
| Understand the ELF being loaded | [15-Native-Code](../../15-Native-Code/README.md) |
