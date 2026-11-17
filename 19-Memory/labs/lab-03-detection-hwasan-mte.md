# Lab 03 — Detection: HWASan, MTE, GWP-ASan, malloc_debug, and reading their reports

> **Objective:** take one buggy source file, run it under every memory checker Android offers, read
> each report properly, and be able to say which checker you would ask a developer to enable and
> what it would cost them.

**Difficulty:** intermediate to advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-reading-proc-maps.md), [Lab 02](lab-02-allocator-behaviour.md).
Chapter 19 §3.11–3.14 and §5.8–5.9 are the reading.

**What you need**

| | |
|---|---|
| A device or emulator | arm64, Android 11+ for HWASan. Android 13+ **on MTE hardware** for Part 4. |
| The NDK | r25 or newer. |
| The fixtures | Built and pushed as in Lab 01 Part 3, **including** `libclang_rt.hwasan-aarch64-android.so`. |

---

## 0. The premise

Lab 02 ended on an uncomfortable fact: a use-after-free on a stock Android device is **silent**. The
program printed its output, corrupted another object, returned zero, and nobody was told.

That is the normal condition of native code. Detection is not automatic; it is something somebody
switched on. This lab is about which switches exist, what each one catches, what each one costs, and
— the part that gets skipped — how to read the output when one fires.

---

## Part 1 — The baseline: what the stock allocator catches on its own

Run all six modes with no checker at all.

```bash
# adb shell
cd /data/local/tmp/ch19
for m in "overflow 1" "overflow 64" uaf dfree invfree stack; do
  echo "===== $m ====="
  ./heap-bugs $m > /dev/null 2>&1
  echo "exit=$?"
done
```

Real results, Android 13, arm64, stock build:

| Mode | The defect | Exit | What happened |
|---|---|---|---|
| `overflow 1` | 1 byte past a 32-byte block | 0 | nothing, not even at `free()` |
| `overflow 64` | 64 bytes past a 32-byte block | 0 | nothing, not even at `free()` |
| `uaf` | read and write after `free()` | 0 | nothing; another object silently corrupted |
| `dfree` | `free()` the same pointer twice | 134 | **SIGABRT** |
| `invfree` | `free()` an interior pointer | 134 | **SIGABRT** |
| `stack` | 40 bytes into a 16-byte array | 135 | **SIGBUS** on return |

### Step 1.1 Read the two aborts

```bash
# host
adb logcat -d -s DEBUG,libc,scudo | grep -E 'Scudo ERROR|Abort message' | tail -5
```

Real output:

```
I scudo : Scudo ERROR: invalid chunk state when deallocating address 0x200007d65782b10
F DEBUG : Abort message: 'Scudo ERROR: invalid chunk state when deallocating address 0x200007d65782b10'

I scudo : Scudo ERROR: corrupted chunk header at address 0x2000071b96fd660
F DEBUG : Abort message: 'Scudo ERROR: corrupted chunk header at address 0x2000071b96fd660'
```

Three things to take from this.

1. **The messages are documented.** AOSP's Scudo page lists exactly these strings — *corrupted chunk
   header*, *race on chunk header*, *invalid chunk state*, *misaligned pointer*, *allocation type
   mismatch*, *invalid sized delete*, *RSS limit exhausted*. When one appears in a crash you are
   triaging, you can look it up rather than guess.
2. **The address in the message is not the address the program printed.** The program printed
   `0xb400007d65782b10`; Scudo reported `0x200007d65782b10`. The top byte differs because Scudo
   applies its own transformation to the tag before reporting. Do not waste an hour trying to
   reconcile them — compare the low 48 bits.
3. **Scudo catches bugs at `free()`, not at the corrupting write.** Both aborts happened inside
   `deallocate`. The overflow modes exit 0 precisely because nothing ever freed the chunk whose
   header was smashed.

### Step 1.2 Read the SIGBUS

```bash
# host
adb logcat -d -s DEBUG | grep -A2 'heap-bugs stack' | head -6
```

Real output:

```
F libc  : Fatal signal 7 (SIGBUS), code 1 (BUS_ADRALN), fault addr 0x42424242424242
F DEBUG : signal 7 (SIGBUS), code 1 (BUS_ADRALN), fault addr 0x0042424242424242
```

`0x42` is `'B'`, and `mode_stack` writes `0x42` forty times. The fault address is made entirely of
bytes the program wrote. That is the whole of "an out-of-bounds stack write reaches something that
gets dereferenced", demonstrated without a single line of exploit code.

**Question 1.** The `overflow 64` case exits 0. A developer says "so it is not a real bug". Answer
them.

<details><summary>Answer</summary>

Exit 0 means nothing was *detected*. Sixty-four bytes were written past the end of a 32-byte
allocation; that memory belongs to the allocator's bookkeeping and to at least one other chunk.
Nothing complained because nothing looked. The corruption is real and its consequences are deferred
to whenever some other code touches the smashed structures — which may be in a different function,
a different thread, or a different feature, and which is why the eventual crash report will point at
innocent code.

The correct next step is not to argue but to demonstrate: run the same binary under HWASan (Part 2)
and show the report naming the exact line, then point out that this is what the crash reports from
the field have been failing to say.

</details>

---

## Part 2 — HWAddressSanitizer

### Step 2.1 What it is, in one paragraph

HWASan gives every 16-byte granule of memory a 1-byte **tag**, stored in a shadow region, and puts a
matching tag in the top byte of every pointer to it. Every load and store the compiler emits is
preceded by a check that the pointer's tag equals the memory's tag. Freeing memory changes the
memory's tag, so a pointer to freed memory no longer matches. Overflowing past an allocation reaches
a granule with a different tag. Both are caught **at the access**, not later.

It needs AArch64 and it needs recompilation. AOSP's own documentation states it plainly:

> "HWASan is only available on Android 10 and higher, and only on AArch64 hardware."

with userspace support from Android 11.

### Step 2.2 Run it

```bash
# adb shell
cd /data/local/tmp/ch19
LD_LIBRARY_PATH=. ./heap-bugs-hwasan uaf
```

> **Warning**
> `LD_LIBRARY_PATH=.` is not optional. The instrumented binary has
> `libclang_rt.hwasan-aarch64-android.so` as a `DT_NEEDED` entry. Without it you get
> `library ... not found`, which reads like a packaging problem and is really a missing push.
> Confirm the dependency yourself:
> ```bash
> # host
> llvm-readelf -d out/heap-bugs-hwasan | head -4
> ```

### Step 2.3 Read the report, field by field

Real output, trimmed:

```
==16035==ERROR: HWAddressSanitizer: tag-mismatch on address 0x0049efff0080 at pc 0x0073185ce0d4
READ of size 1 at 0x0049efff0080 tags: e3/a7 (ptr/mem) in thread T0
    #0 0x73185ce0d4  (/data/local/tmp/ch19/heap-bugs-hwasan+0x30d4)

[0x0049efff0080,0x0049efff00c0) is a small unallocated heap chunk; size: 64 offset: 0

Cause: use-after-free
0x0049efff0080 is located 0 bytes inside of 64-byte region [0x0049efff0080,0x0049efff00c0)
freed by thread T0 here:
    #0 ... (libclang_rt.hwasan-aarch64-android.so+0x208dc)
    #1 0x73185ce048  (heap-bugs-hwasan+0x3048)

previously allocated here:
    #0 ... (libclang_rt.hwasan-aarch64-android.so+0x20f88)
    #1 0x73185cdf84  (heap-bugs-hwasan+0x2f84)

Memory tags around the buggy address (one tag corresponds to 16 bytes):
=>0x006f9efff000: 76  76  76  00  64  64  64  00 [a7] a7  a7  a7  00  00  00  00
```

| Part of the report | What it tells you | Why it matters |
|---|---|---|
| `tag-mismatch on address 0x…` | the **untagged** address that was accessed | this is the number to compare with maps |
| `at pc 0x…` | where the faulting instruction is | subtract the module base for Ghidra |
| `READ of size 1` | the access, not the allocation | a 1-byte read is enough; there is no minimum |
| `tags: e3/a7 (ptr/mem)` | pointer tag vs memory tag | they differ, which *is* the bug |
| `Cause: use-after-free` | HWASan's own classification | it distinguishes UAF from overflow for you |
| `is located 0 bytes inside of 64-byte region` | offset within the allocation | `0 bytes to the right of` would mean an overflow |
| `freed by thread T0 here` | **the free stack** | the line that released it |
| `previously allocated here` | **the allocation stack** | the line that created it |
| the tag map | one byte per 16-byte granule | `[a7]` is the granule you touched; `00` is unallocated |

The two extra stack traces are the reason HWASan is worth its cost. A conventional crash tells you
where the program died. HWASan tells you where the object was born, where it was killed, and where
the ghost was touched.

### Step 2.4 Symbolise the stacks

Raw offsets are usable but tedious. Symbolise them:

```bash
# host
llvm-symbolizer --obj=out/heap-bugs-hwasan 0x30d4 0x3048 0x2f84
```

### Step 2.5 The overflow report is a different shape

```bash
# adb shell
LD_LIBRARY_PATH=. ./heap-bugs-hwasan overflow 1
```

Real output, trimmed:

```
WRITE of size 1 at 0x004eefff0040 tags: a0/00 (ptr/mem) in thread T0
Cause: heap-buffer-overflow
0x004eefff0040 is located 0 bytes to the right of 32-byte region [0x004eefff0020,0x004eefff0040)
allocated here:
    ...
```

Note the differences from the UAF report: `Cause: heap-buffer-overflow`, `to the right of` instead of
`inside of`, memory tag `00` (unallocated) instead of a live tag, and **no free stack**, because
nothing was freed.

### Step 2.6 The control

This is the step people skip and it is the one that makes the rest trustworthy.

```bash
# adb shell
LD_LIBRARY_PATH=. ./heap-bugs-fixed-hwasan selftest; echo "exit=$?"
```

Expected: the program prints its four cases and exits **0**, with no sanitiser output at all.

A checker that fires on the buggy build and stays silent on the fixed build is a checker whose
verdict on unknown code means something. A checker that is silent on both is not switched on.

**Question 2.** Your HWASan build of a real app runs and reports nothing. Give three explanations
that are not "the app has no memory bugs", and how you would rule each one out.

<details><summary>Answer</summary>

1. **The instrumentation is not actually there.** Only the code compiled with `-fsanitize=hwaddress`
   is instrumented; a prebuilt `.so` you did not rebuild is not. Rule it out by running the *known
   buggy* fixture in the same session and confirming it fires.
2. **The runtime did not load.** Check for `libclang_rt.hwasan-*.so` in the process's maps, or for
   `SizeClassAllocator` in the allocator fingerprint from `maps-analyse.py`. If Scudo is still the
   allocator, HWASan is not running.
3. **The buggy path was not executed.** A sanitiser only sees code that runs. Rule it out by
   measuring coverage, or at minimum by driving the specific feature you are testing rather than
   launching the app and watching the splash screen.

A fourth worth mentioning: on a non-HWASan device, running HWASan apps was not supported before
Android 14, where the `wrap.sh` + `LD_HWASAN=1` route exists. On an older device you need a
HWASan-enabled system image.

</details>

---

## Part 3 — GWP-ASan: the one that is already on

HWASan requires recompiling and costs real performance. GWP-ASan requires neither. It samples a tiny
fraction of allocations, places each sampled one against a `PROT_NONE` guard page, and lets the MMU
do the checking. AOSP's documentation is explicit:

> "GWP-ASan does not require source or recompilation (that is, works with prebuilts), and works on
> both 32- and 64-bit processes."

and

> "On devices that run Android 14 (API level 34) or higher, all apps use Recoverable GWP-ASan by
> default."

with sampling at roughly 1% of app launches for the recoverable variant.

### Step 3.1 See the mechanism first

```bash
# adb shell
/data/local/tmp/ch19/mem-landmarks guard
```

Real output:

```
  three pages at 0x7087874000, middle one set to PROT_NONE:
    7087874000-7087875000 rw-p 00000000 00:00 0
    7087875000-7087876000 ---p 00000000 00:00 0
    7087876000-7087877000 rw-p 00000000 00:00 0

  now writing forward from the first page, one byte at a time:
  faulted with signal 11 (si_code 2)
```

That `---p` line **is** the mechanism. There is no clever algorithm; there is a page with no
permissions in the way.

### Step 3.2 Turn it on for an app

```xml
<!-- AndroidManifest.xml -->
<application android:gwpAsanMode="always">
```

The three documented values are `never`, `default` and `always`. Then look for its regions:

```bash
# host
adb shell "cat /proc/self/maps" | grep -i gwp        # your own process, for the shape
```

```javascript
// Frida, in the target
rpc.exports.find('GWP')
```

or capture the maps through Frida and run the analyser, which reports GWP-ASan in its ALLOCATOR
block.

### Step 3.3 Understand what sampling means for you as a tester

**GWP-ASan will not find your bug on demand.** At roughly 1% of allocations, a bug on a code path
you trigger once will almost certainly be missed. It is a *fleet* tool: across a million installs,
1% sampling finds the bugs that matter because they happen constantly somewhere.

For a pentest, that makes GWP-ASan:

- **worth turning on** in a test build, because it is free and sometimes gets lucky,
- **worth recommending** to the client, because it costs them nothing in production,
- **useless as a negative result.** "We ran with GWP-ASan and found nothing" is not evidence.

**Question 3.** A client asks whether they should enable `android:gwpAsanMode="always"` in
production. What do you say?

<details><summary>Answer</summary>

Yes, with one caveat and one correction.

The caveat: `always` raises the sampling rate compared with the default, which costs a small amount
of memory and a negligible amount of CPU. Recommend measuring on a low-end device rather than
assuming.

The correction: on Android 14 and higher the recoverable variant is already on by default, so the
question is really "should we opt into more than the default", not "should we opt in". And on
Android 13 and lower it is off for non-system apps, so `always` is a genuine change there.

Also set the expectation: this is a crash-quality improvement, not a security control they can point
at in an audit. It makes some latent bugs visible; it does not prevent exploitation of the ones it
misses.

</details>

---

## Part 4 — MTE, if you have the hardware

Memory Tagging Extension is HWASan's idea implemented in silicon. Arm introduced it in Armv8.5-A;
AOSP documents Android 12 as the first release with kernel and allocator support, and states that
"Starting from Android 13, select devices have support for MTE".

Unlike HWASan, MTE needs **no recompilation for heap tagging** — bionic's allocator tags heap
allocations itself. It does need the hardware.

### Step 4.1 Find out whether you have it

```bash
# adb shell
grep -o 'mte' /proc/cpuinfo | head -1
getprop ro.arm64.memtag.bootctl
getprop | grep -i memtag
```

If nothing comes back, you do not have MTE and Part 4 is a reading exercise. That is the common
case; do not spend an afternoon on it.

### Step 4.2 The three modes

| Mode | What it does | Signal on failure | Cost |
|---|---|---|---|
| `off` | no checking | — | none |
| `async` | checks are deferred to the next kernel entry | `SIGSEGV` code `SEGV_MTEAERR` | low; suitable for production |
| `sync` | every access checked immediately, precise report | `SIGSEGV` code `SEGV_MTESERR` | higher; for debugging |
| `asymm` | sync on reads, async on writes (Armv8.7-A) | — | between the two |

The trade is the same one as everywhere else in this chapter: `async` tells you *that* something went
wrong, `sync` tells you *where*.

### Step 4.3 The four ways to turn it on

```xml
<!-- 1. manifest, on <application> or <process> -->
<application android:memtagMode="sync" />
```

```bash
# 2. app compatibility change, no rebuild needed
adb shell am compat enable NATIVE_MEMTAG_SYNC com.example.target
adb shell am compat enable NATIVE_MEMTAG_ASYNC com.example.target

# 3. system property, per process basename
adb shell setprop arm64.memtag.process.<basename> sync

# 4. environment variable, for native processes; takes precedence over the property
MEMTAG_OPTIONS=sync ./some-native-binary
```

There is also a Developer Options toggle: *Settings → Developer options → Memory Tagging Extension*.

> **Warning — a verified toolchain limitation**
> Heap tagging needs no rebuild. **Stack** tagging does, and the flags are newer than they look.
> On NDK r25c (clang 14.0.7), verified by running the compiler:
>
> ```
> $ aarch64-linux-android29-clang -fsanitize=memtag -fsanitize-memtag-mode=sync ...
> clang: error: unknown argument: '-fsanitize-memtag-mode=sync'
>
> $ aarch64-linux-android29-clang -fsanitize=memtag-stack ...
> clang: error: unsupported argument 'memtag-stack' to option 'fsanitize='
> ```
>
> `-fsanitize=memtag` alone *is* accepted and does produce a larger binary, but it does **not** emit
> the `.note.android.memtag` ELF note that Android's loader reads. Stack tagging needs Android 14
> QPR3 or later and a newer NDK. `build-memory-fixtures.sh` therefore does not ship an MTE fixture,
> and says so rather than pretending.

### Step 4.4 If you do have MTE hardware

```bash
# adb shell
adb shell am compat enable NATIVE_MEMTAG_SYNC com.example.target
# then drive the app and watch for
adb logcat | grep -E 'SEGV_MTESERR|SEGV_MTEAERR'
```

**Question 4.** MTE is described as "HWASan in hardware". Name two things HWASan gives you that MTE
does not, and one thing MTE gives you that HWASan does not.

<details><summary>Answer</summary>

HWASan gives you:
1. **Allocation and free stack traces in the report.** MTE's `SEGV_MTESERR` gives you a faulting
   address and a register state; the allocator has to be recording history separately for you to get
   more.
2. **A larger tag space and no hardware requirement beyond AArch64.** HWASan uses a full byte and
   works on any AArch64 device; MTE uses 4 bits — 16 possible tags — so roughly 1 in 16 mismatches
   happen to collide and go undetected, and it needs Armv8.5-A silicon.

MTE gives you:
- **Production-viable overhead.** HWASan roughly doubles memory and costs significant CPU; it is a
  test-build tool. MTE in `async` mode is cheap enough to ship, which means it catches bugs on real
  users' devices rather than only on the ones you thought to test.

</details>

---

## Part 5 — malloc_debug: the one that needs no rebuild at all

bionic ships a debug allocator that can be switched on with a system property. It needs no
recompilation and no sanitiser runtime, which makes it the only option for a prebuilt third-party
`.so` you cannot rebuild.

```bash
# adb shell, as root or on a debuggable app
setprop libc.debug.malloc.options "guard fill free_track backtrace"
setprop libc.debug.malloc.program heap-bugs

# for an app, API 26 and later:
setprop wrap.com.example.target '"LIBC_DEBUG_MALLOC_OPTIONS=backtrace logwrapper"'
```

The options, with their documented defaults:

| Option | Default | What it does |
|---|---|---|
| `front_guard[=N]` | 32 bytes | a pattern before each allocation; checked on free |
| `rear_guard[=N]` | 32 bytes | a pattern after each allocation; checked on free |
| `guard[=N]` | 32 bytes | both of the above |
| `backtrace[=N]` | 16 frames | record the allocation stack |
| `backtrace_enable_on_signal[=N]` | 16 frames | start recording when signalled, not from boot |
| `fill_on_alloc[=N]` | — | fill new allocations with a pattern, so uninitialised use is visible |
| `fill_on_free[=N]` | — | fill freed allocations, so use-after-free reads garbage rather than stale data |
| `free_track[=N]` | 100 | keep N freed allocations quarantined and check them for later writes |
| `leak_track` | — | report allocations still live at exit |
| `expand_alloc[=N]` | 16 bytes | make every allocation bigger, so small overflows land in slack |
| `verify_pointers` | — | check that a pointer passed to free was returned by malloc |
| `abort_on_error` | — | abort on detection rather than logging |
| `record_allocs[=N]` | 8,000,000 | record every allocation to a file for offline analysis |

> **Pentester's Note**
> `fill_on_free` is the one to reach for when you are chasing a use-after-free by hand. It makes the
> residue in a freed block a recognisable pattern instead of the old contents, so a UAF read
> produces visibly wrong data instead of plausibly correct data. Combined with `free_track`, you
> get "this freed block was written to after it was freed, and here is the allocation stack".

**Question 5.** Rank HWASan, MTE (sync), GWP-ASan and malloc_debug by *what you would ask for*, for
each of these three situations: (a) the client's own CI, (b) a two-week black-box pentest of a
release APK, (c) a production fleet of ten million installs.

<details><summary>Answer</summary>

**(a) CI:** HWASan, easily. It needs a rebuild, which CI already does; it catches the most; the
overhead does not matter when nothing is waiting on the result. Add UBSan alongside it. Anything
else is a compromise you do not need to make here.

**(b) Two-week black-box pentest of a release APK:** malloc_debug first, because it is the only one
that works on a prebuilt binary you cannot rebuild, and GWP-ASan second because it costs nothing to
enable. HWASan is out — you cannot rebuild the app. MTE is out unless you happen to have the
hardware and the app happens to be reachable through `am compat`. Be honest in the report that your
detection coverage was weak and that "no memory-safety findings" therefore carries little weight.

**(c) Production fleet:** MTE in `async` mode where the hardware supports it, and GWP-ASan
everywhere else. Both are cheap enough to ship, and at fleet scale sampling stops being a weakness:
1% of ten million launches is a hundred thousand samples a day. HWASan is not shippable. malloc_debug
is a debugging tool, not a production one.

</details>

---

## Success criteria

- [ ] You can state which of the six defects the stock allocator catches, and *why* it catches those
      and not the others.
- [ ] You can read a HWASan report and name the allocation site, the free site, the access, and the
      cause, without help.
- [ ] You can explain the difference between the UAF report and the overflow report in one sentence.
- [ ] You ran the control — the fixed build under HWASan — and it was silent.
- [ ] You can explain the guard-page mechanism behind GWP-ASan and why sampling makes a negative
      result meaningless.
- [ ] You can list the four ways to enable MTE and the two things it does not give you.
- [ ] You can pick the right checker for a given engagement and defend the choice.

---

## Where to go next

| If you want to | Go to |
|---|---|
| Put it all together under time pressure | [Lab 04 — CTF](lab-04-ctf-the-quiet-corruption.md) |
| Re-read the allocator behaviour these checkers replace | [Lab 02](lab-02-allocator-behaviour.md) |
| Check the build-time mitigations rather than the runtime ones | [15-Native-Code](../../15-Native-Code/README.md) §5 |
| Work out whether a third-party library is the source | [17-Libraries](../../17-Libraries/README.md) |
| Hook the allocator yourself | [`../scripts/malloc-trace.js`](../scripts/malloc-trace.js) |
