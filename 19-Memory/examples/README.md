# 19 — Memory — Examples

Four sources, one build script, one fixture. **Everything here was compiled and run** before it
shipped; this file records what was verified, on what, and — as importantly — what was not.

---

## The files

| File | What it is |
|---|---|
| [`heap-bugs.c`](heap-bugs.c) | Six native memory-safety behaviours, one per mode, plus a `layout` mode with no bug at all |
| [`heap-bugs-fixed.c`](heap-bugs-fixed.c) | The remediated counterpart. Must run clean and silent under HWASan |
| [`mem-landmarks.c`](mem-landmarks.c) | Address-space landmarks, page size, `mprotect` enforcement, guard pages |
| [`build-memory-fixtures.sh`](build-memory-fixtures.sh) | Builds the above seven ways and copies the sanitiser runtimes out of the NDK |
| [`fixture-app-maps.txt`](fixture-app-maps.txt) | A **synthetic** app-process maps capture for Labs 01 and 04. Its own header explains at length why it is synthetic |

---

## Build and run

```bash
# host
export ANDROID_HOME="$HOME/Android/Sdk"
./build-memory-fixtures.sh /tmp/ch19

adb shell mkdir -p /data/local/tmp/ch19
adb push /tmp/ch19/. /data/local/tmp/ch19/
adb shell chmod 755 /data/local/tmp/ch19/heap-bugs \
                    /data/local/tmp/ch19/heap-bugs-hwasan \
                    /data/local/tmp/ch19/heap-bugs-fixed \
                    /data/local/tmp/ch19/heap-bugs-fixed-hwasan \
                    /data/local/tmp/ch19/mem-landmarks
```

```bash
# adb shell
cd /data/local/tmp/ch19
./heap-bugs layout
LD_LIBRARY_PATH=. ./heap-bugs-hwasan uaf
LD_LIBRARY_PATH=. ./heap-bugs-fixed-hwasan selftest; echo "exit=$?"
./mem-landmarks wx
./mem-landmarks guard
```

> **Two traps that will cost you twenty minutes each.**
>
> **Git Bash mangles `adb push` destinations.** `adb push x /data/local/tmp/` becomes
> `C:/Program Files/Git/data/local/tmp/` and fails with `remote secure_mkdirs failed`. Prefix with
> `MSYS_NO_PATHCONV=1`, or use PowerShell or `cmd`.
>
> **Some devices refuse to `exec` from `/data/local/tmp`.** The error is
> `./heap-bugs: No such device or address`, which sounds like nothing. Run through the loader with an
> absolute path instead: `/system/bin/linker64 /data/local/tmp/ch19/heap-bugs layout`.

---

## What was verified, and on what

**Build host:** Windows, NDK **25.2.9519653** (clang 14.0.7), targeting API 29.
**Run target:** a stock **Android 13 (API 33)**, `arm64-v8a`, non-low-RAM device, over `adb`, as the
unprivileged `shell` user (uid 2000). No root.

| Fixture | Built | Warnings | Ran on device |
|---|---|---|---|
| `heap-bugs` (arm64) | yes | **0** with `-Wall -Wextra` | yes, all six modes |
| `heap-bugs-hwasan` | yes | 0 | yes — **the sanitizer fired** |
| `heap-bugs-asan` | yes | 0 | built only |
| `heap-bugs-fixed` | yes | 0 | yes, exit 0 |
| `heap-bugs-fixed-hwasan` | yes | 0 | yes, **exit 0 and silent** |
| `mem-landmarks` | yes | 0 | yes, all four modes |
| `heap-bugs-arm32` (armeabi-v7a) | yes | 0 | yes, `layout` mode |

### Results that the chapter's prose rests on

| Claim | Verified how |
|---|---|
| Heap pointers carry a `0xb4` tag on 64-bit | `heap-bugs layout` printed `0xb400007cbeeee2e0` for a region starting `0x7cbeeee000` |
| No tag on 32-bit | `heap-bugs-arm32 layout` printed `0xef440970` — plain |
| The native heap is `[anon:scudo:primary]` | `heap-bugs layout` resolved its own allocation to that region |
| Large allocations move to `[anon:scudo:secondary]` | the 4 MiB allocation landed there; the 64 KiB one did not |
| Allocation order within a size class is randomised | eight consecutive `malloc(32)` calls gave non-monotonic deltas |
| Stride for a 32-byte request is 48 bytes | every delta was a multiple of 48 |
| The quarantine is off — reuse is immediate | `free` then `malloc(32)` returned the **same address** |
| Freed memory is not zeroed | the same 16 bytes read back after `free()` |
| Scudo catches double free | exit 134, `Scudo ERROR: invalid chunk state when deallocating address 0x…` |
| Scudo catches invalid free | exit 134, `Scudo ERROR: corrupted chunk header at address 0x…` |
| Scudo misses overflows | `overflow 1` and `overflow 64` both exited **0**, silently, even at `free()` |
| Scudo misses use-after-free | `uaf` exited 0; byte 0 of a *different* object was changed to `0x41` |
| A stack overflow reaches something dereferenced | `SIGBUS BUS_ADRALN, fault addr 0x42424242424242` — made of the bytes the program wrote |
| HWASan replaces the allocator | region names became `[anon:SizeClassAllocator: region data]` and `[anon:LargeMmapAllocator]` |
| HWASan reuses the same address with a **new tag** | `SAME ADDRESS ... DIFFERENT TAG (07 -> 1d)` |
| HWASan catches use-after-free | `Cause: use-after-free`, with the allocation **and** free stacks |
| HWASan catches heap-buffer-overflow | `Cause: heap-buffer-overflow`, `0 bytes to the right of` |
| The fixed source is silent under HWASan | `selftest` printed its four cases and exited 0 with no sanitiser output |
| `mprotect` is enforced by hardware | `mem-landmarks wx`: `faulted with signal 11 (si_code 2)` after removing write permission |
| A `PROT_NONE` page stops a linear overflow at once | `mem-landmarks guard`: fault at the page boundary |
| `shell` cannot read another process's maps | `head: /proc/541/maps: Permission denied` for `zygote64` |

### Two claims the running corrected

Both were written from the textbook answer and both were **wrong on a real device**. The sources now
say what was measured, and say that they are measurements.

1. **"Scudo quarantines a freed block, so you will not get it straight back."** False on Android:
   the quarantine size is zero by default and reuse is immediate. `QuarantineSizeKb` is a real Scudo
   option with a non-zero upstream default; Android chose the memory.
2. **"Scudo zeroes memory on free."** False: the bytes were unchanged. `ZeroContents` exists and is
   not enabled.

This is why the chapter tells you to measure rather than quote. Two of its own claims did not survive
contact with a device.

### One toolchain limitation, verified rather than assumed

`explicit_bzero()` — recommended by essentially every guide to clearing secrets — is **absent from
the NDK r25c sysroot entirely**:

```bash
grep -rn explicit_bzero \
  $NDK/toolchains/llvm/prebuilt/<host>/sysroot/usr/include
# (no output)
```

and a build that calls it fails with `ld: error: undefined symbol: explicit_bzero`. `memset_s` is
absent too. `heap-bugs-fixed.c` therefore uses a `volatile` write loop, and explains why in a comment
rather than silently.

Likewise, NDK r25c accepts `-fsanitize=memtag` but rejects `-fsanitize-memtag-mode=sync` and
`-fsanitize=memtag-stack`, and emits no `.note.android.memtag` section. `build-memory-fixtures.sh`
therefore ships **no MTE fixture**, and says so, rather than shipping one that silently does nothing.

### What was NOT verified

- **MTE.** The test device has no MTE hardware. Everything the chapter says about MTE comes from
  AOSP and Arm documentation, is quoted as such, and was not observed.
- **`heap-bugs-asan`.** Built clean; not run.
- **A low-RAM device.** The jemalloc-on-low-memory-devices exception is documented by AOSP and was
  not observed here.
- **A 16 KiB-page device.** `mem-landmarks pagesize` reported 4096. The 16 KiB material is from the
  Android developer documentation.
- **Any real third-party app.** Every measurement above is from these fixtures, run as `shell`.

---

## A note on the fixture

[`fixture-app-maps.txt`](fixture-app-maps.txt) is **constructed**, not captured, and its header says
so in detail. The reason is in the table above: an unprivileged `adb shell` on Android 13 is denied
read access to another process's `/proc` entries, so a lab that says "now read the target app's
maps" cannot be done by a reader without root. A synthetic fixture labelled as such is the honest
alternative to pretending otherwise.

Its *structure* is faithful — segment counts, permission patterns, ART space names, Scudo region
names, the boot image and OAT layout. Its *addresses* are invented and internally consistent. Do not
quote an address from it as evidence of anything.

---

## Related

| | |
|---|---|
| The scripts that consume these | [`../scripts/`](../scripts/) |
| The labs that use them | [`../labs/`](../labs/) |
| ELF-level inspection of what you built | [15-Native-Code](../../15-Native-Code/README.md) |
| The chapter | [`../README.md`](../README.md) |
