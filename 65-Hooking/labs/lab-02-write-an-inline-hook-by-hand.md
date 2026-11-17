# Lab 02 — Write an inline hook by hand

> **Objective.** Build a shared library, disassemble one of its functions, overwrite its prologue
> with a branch to code of your own, relocate the instructions you displaced, jump back, flush the
> instruction cache, and **prove** the hook worked — including proving that the original function
> body still ran. No Frida. No root. No hooking library. Approximately 250 lines of C, every byte of
> which you will understand.

**Difficulty:** advanced — this is the chapter's spine
**Time:** 3 hours the first time
**Prerequisites:** [18-ARM §3.3, §3.4, §3.6, §3.8](../../18-ARM/README.md),
[15-Native-Code](../../15-Native-Code/README.md), [Lab 01](lab-01-the-five-hook-types.md)
**Device used to verify this lab:** `i9000S`, Android 13 / API 33, **unrooted, no frida-server**,
8× Cortex-A53 (`CPU implementer 0x41`, `CPU part 0xd03`). NDK 25.2.9519653, clang 14.0.7.
Every hexadecimal value printed in this lab was produced on that device or by that toolchain.

---

## 0. The claim you are about to test

> An inline hook is six steps. Five of them are bookkeeping. The sixth — relocating a PC-relative
> instruction — is the only one that requires you to understand the instruction set, and it is the
> reason inline hooking is hard.

---

## 1. Setup

```bash
# host
cd 65-Hooking/examples
export ANDROID_NDK=$HOME/Android/Sdk/ndk/25.2.9519653
./build-hook-fixtures.sh
```

Keep `$OUT` (printed by the script) in your shell. Confirm the toolchain:

```bash
# host
$ANDROID_NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android21-clang --version
```

---

## 2. Look at what you are about to attack

Everything starts with the disassembly. Do not skip this; the whole lab is determined by four
instruction words.

```bash
# host
$ANDROID_NDK/toolchains/llvm/prebuilt/*/bin/llvm-objdump -d --section=.text $OUT/libguard.so |
    sed -n '/<guard_check>:/,/^$/p'
```

Measured output:

```
0000000000001714 <guard_check>:
    1714: fd 7b bf a9   stp  x29, x30, [sp, #-16]!
    1718: fd 03 00 91   mov  x29, sp
    171c: 08 00 00 b0   adrp x8, 0x2000 <guard_check+0xc>
    1720: 08 ad 44 f9   ldr  x8, [x8, #2392]
    1724: 09 01 40 b9   ldr  w9, [x8]
    1728: 29 05 00 11   add  w9, w9, #1
    172c: 09 01 00 b9   str  w9, [x8]
    1730: c0 00 00 b4   cbz  x0, 0x1748 <guard_check+0x34>
    1734: e1 ff ff f0   adrp x1, 0x0 <guard_check+0x1c>
    1738: 21 00 16 91   add  x1, x1, #1408
    173c: 1d 00 00 94   bl   0x17b0 <strcmp@plt>
    1740: 1f 00 00 71   cmp  w0, #0
    1744: e0 17 9f 1a   cset w0, eq
    1748: fd 7b c1 a8   ldp  x29, x30, [sp], #16
    174c: c0 03 5f d6   ret
```

### 2.1 Reading the bytes as words

`llvm-objdump` prints bytes in file order. AArch64 is little-endian, so the **instruction word** is
those bytes reversed:

| Address | Bytes in file | Word | Instruction |
|---|---|---|---|
| `+0` | `fd 7b bf a9` | `a9bf7bfd` | `stp x29, x30, [sp, #-16]!` |
| `+4` | `fd 03 00 91` | `910003fd` | `mov x29, sp` |
| `+8` | `08 00 00 b0` | `b0000008` | `adrp x8, …` |
| `+12` | `08 ad 44 f9` | `f944ad08` | `ldr x8, [x8, #2392]` |

Get comfortable with that conversion now. Every value the hook prints is a **word**, and every value
a hex editor shows you is **bytes**. Confusing the two is the most common reason a hand-written patch
lands backwards.

### 2.2 The one instruction that makes this a real lab

`adrp x8, 0x2000` at `+8`.

`adrp` means "form the address of a 4 KiB page, relative to **my own address**". Its encoding does
not contain `0x2000`; it contains the number of pages from *here* to *there*. Move the instruction to
a different address and it computes a different answer, with no error, no fault and no hint that
anything is wrong.

> **Definition — PC-relative.** An instruction is *PC-relative* when its effect depends on the
> address at which it executes. Copying such an instruction to a new address changes its meaning.
> On AArch64 the PC-relative forms are `adr`, `adrp`, `ldr` (literal), `b`, `bl`, `b.cond`,
> `cbz`/`cbnz` and `tbz`/`tbnz`. Everything else — arithmetic, register-offset loads and stores,
> moves — is position independent and can be copied verbatim.

---

## 3. Ask the analyser before you touch anything

```bash
# host
cd 65-Hooking/scripts
python3 -B hookability.py $OUT/libguard.so --symbol guard_check
```

Measured output:

```
========================================================================
guard_check  @ 0x1714  (size 60 bytes)
========================================================================
patch model     : 16-byte absolute jump (ldr x16,#8 / br x16 / .quad)
callers in file : 0

displaced instructions:
  +0    a9bf7bfd  copy
  +4    910003fd  copy
  +8    b0000008  RELOC adrp
        PC-relative: forms page 0x2000. Re-encodable at any new address within +/-4 GiB of that page.
  +12   f944ad08  copy

WARNINGS:
  [?] no `bl` in this file targets 0x1714. Either the function is only called from
      another module, or -- far more often at -O2 -- the compiler INLINED its body
      into its callers and this standalone copy is dead.

VERDICT: NEEDS RELOCATION
```

Four facts, before a single byte has been written:

1. The function is 60 bytes; a 16-byte patch fits.
2. Three of four displaced instructions are position independent.
3. One is an `adrp` and **must be re-encoded**.
4. Nothing in this file calls it — here that is expected (it is exported for external callers), but
   on a real target it is the warning that saves you an afternoon. Lab 03 is about that.

---

## 4. The patch you will write

You need to overwrite the start of `guard_check` with a branch to your replacement. There are two
ways, and choosing between them is a real decision.

### 4.1 Option A — a 4-byte direct branch

```
+0   b <replacement>          0x14000000 | (imm26)
```

**Cost:** 4 bytes, so you displace only one instruction.
**Limit:** `b`'s immediate is 26 bits, scaled by 4 and signed, giving a reach of **±128 MiB**. If
your replacement is further away than that, you cannot encode the branch.

### 4.2 Option B — a 16-byte absolute jump

```
+0   ldr x16, #8              0x58000050
+4   br  x16                  0xd61f0200
+8   .quad <replacement>      (8 bytes of data, executed by nothing)
```

**Cost:** 16 bytes, so you displace four instructions and inherit four relocation problems.
**Limit:** none. It carries the full 64-bit address.

This lab uses **Option B**, because it is what a general-purpose engine must do and because it forces
you to confront the `adrp`.

### 4.3 Why `x16`

`x16` is **IP0**, the first intra-procedure-call scratch register. AAPCS64 states that a linker or
veneer may clobber IP0 and IP1 at a call boundary, so no correct code may hold a live value in `x16`
across a function entry. That is exactly why every real hooking engine uses `x16` or `x17` here. See
[18-ARM §3.4](../../18-ARM/README.md).

### 4.4 Where the encodings come from

**Never write an instruction encoding from memory.** Every value in this lab came from a round trip:

```bash
# host
cat > /tmp/enc.s <<'EOF'
    .text
    .globl _enc
_enc:
    ldr  x16, 8
    br   x16
    ret
    nop
    mov  w0, #1
EOF
$NDK/aarch64-linux-android21-clang -c -x assembler /tmp/enc.s -o /tmp/enc.o
$NDK/llvm-objdump -d /tmp/enc.o
```

Measured:

```
0000000000000000 <_enc>:
       0: 50 00 00 58   ldr  x16, 0x8 <_enc+0x8>
       4: 00 02 1f d6   br   x16
       8: c0 03 5f d6   ret
       c: 1f 20 03 d5   nop
      10: 20 00 80 52   mov  w0, #1
```

| Instruction | Word | Bytes in file |
|---|---|---|
| `ldr x16, #8` | `0x58000050` | `50 00 00 58` |
| `br x16` | `0xd61f0200` | `00 02 1f d6` |
| `ret` | `0xd65f03c0` | `c0 03 5f d6` |
| `nop` | `0xd503201f` | `1f 20 03 d5` |
| `mov w0, #1` | `0x52800020` | `20 00 80 52` |

The last four agree exactly with
[`18-ARM/scripts/arm64-patch.py --show-encodings`](../../18-ARM/scripts/arm64-patch.py), which is the
repository's verified table. `ldr x16, #8` and `br x16` were added by the round trip above.

---

## 5. Build the hook, step by step

Open [`../examples/trampoline-hook.c`](../examples/trampoline-hook.c) and follow along. Do not just
run it — the file is written to be read in this order.

### Step 1 — find the target

```c
void *h = dlopen("/data/local/tmp/libguard.so", RTLD_NOW);
guard_fn target = (guard_fn)dlsym(h, "guard_check");
```

`dlsym` gives you the **runtime** address. The `0x1714` you saw in `objdump` is a **file** address;
the difference is the load base, which is chosen by the kernel at load time and differs on every run.

### Step 2 — decide how many instructions to displace

16 bytes of patch, 4 bytes per instruction, so four instructions. Fixed by the patch form, not by
the function.

### Step 3 — allocate a trampoline within range

This is where the first real surprise lives.

```c
void *hint = (void *)(((uintptr_t)target & ~(PAGE - 1)) + 0x100000);
uint32_t *tp = mmap(hint, PAGE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
```

That is the obvious code, and on this device it **failed**:

```
trampoline page @ 0x7c9c435000  (delta from target = +11097491692 bytes)

== RELOCATING 4 displaced instructions ==
cannot relocate instruction 2 (b0000008) - aborting
```

The kernel returned a page **10.3 GiB** away. An `mmap` hint is advisory — the kernel is free to
ignore it entirely, and here it did. `adrp` reaches ±4 GiB, so relocation was impossible and the
engine correctly refused.

The fix is to make the request non-advisory and search:

```c
static void *alloc_near(void *near) {
    uintptr_t base = (uintptr_t)near & ~(uintptr_t)(PAGE - 1);
    for (long k = 1; k < 4096; k++) {
        for (int below = 0; below < 2; below++) {
            uintptr_t want = below ? base - k * PAGE : base + k * PAGE;
            void *r = mmap((void *)want, PAGE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (r == MAP_FAILED) continue;
            if (r == (void *)want) return r;
            munmap(r, PAGE);
        }
    }
    return MAP_FAILED;
}
```

`MAP_FIXED_NOREPLACE` means "map here or fail" — unlike bare `MAP_FIXED`, which would silently
destroy whatever mapping already occupied that address. With it, the trampoline landed **10,004
bytes below** the target.

> **Warning.** Never use bare `MAP_FIXED` to place a trampoline. If something is already mapped
> there — another library's text, the heap, a thread stack — `MAP_FIXED` unmaps it without asking and
> the process dies later, somewhere else, for no visible reason.

> **Pentester's Note.** This is the practical reason production hooking engines allocate from a
> pool of pages reserved near each loaded module rather than calling `mmap` per hook. The range
> constraint is not theoretical; it is the first thing that breaks.

### Step 4 — relocate the displaced instructions

Copy the position-independent ones verbatim. Re-encode the `adrp`.

`adrp Rd, <label>` is encoded as:

```
 31  30 29   28..24   23..................5   4..0
  1  immlo   1 0 0 0 0  immhi (19 bits)        Rd
```

It computes `(PC & ~0xFFF) + (SignExtend(immhi:immlo) << 12)`. The immediate is a **signed count of
4 KiB pages**, 21 bits wide, giving ±4 GiB.

To move it, recover the page it targeted, then recompute the count from the new address:

```c
uintptr_t page  = (old_pc & ~0xFFF) + (adrp_imm(w) << 12);
int64_t   delta = (int64_t)(page - (new_pc & ~0xFFF)) >> 12;
*out = adrp_encode(w, delta);
```

Measured, on the run whose target was at `0x71f982b714`:

```
    [copy ] a9bf7bfd  (position independent)
    [copy ] 910003fd  (position independent)
    [reloc] adrp b0000008 -> f0000008   (target page 0x71f982c000, imm 1 -> 3)
    [copy ] f944ad08  (position independent)
```

Check the arithmetic by hand — this is the moment the lab either lands or does not:

- The original `adrp` is at `0x71f982b71c`. Its page is `0x71f982b000`. Its immediate is 1.
  Target page = `0x71f982b000 + (1 << 12)` = **`0x71f982c000`**.
- The relocated copy is at `0x71f9829008`. Its page is `0x71f9829000`.
  Required immediate = `(0x71f982c000 - 0x71f9829000) >> 12` = `0x3000 >> 12` = **3**.
- Encode 3 into the immediate field: `immlo` = `3 & 3` = 3, `immhi` = `3 >> 2` = 0.
  `b0000008` with `immlo` replaced by 3: `0xb0000008 | (3 << 29)` = **`0xf0000008`**.

That matches the measured output exactly. The instruction changed; its meaning did not.

> **Under the Hood.** Cross-check against static analysis: `hookability.py` reported the target
> page as `0x2000` in **file** terms. The library's load base on that run was `0x71f982a000`
> (`0x71f982b714 − 0x1714`). `0x71f982a000 + 0x2000` = `0x71f982c000`. The static analyser and the
> running process agree to the byte. When your static and dynamic pictures agree like this, you are
> almost certainly reading both correctly.

### Step 5 — append the jump back, and make the trampoline executable

```c
put_abs_jump(&tp[4], (uintptr_t)target + 16);
mprotect(tp, PAGE, PROT_READ | PROT_EXEC);
__builtin___clear_cache((char *)tp, (char *)tp + PAGE);
```

The trampoline is now:

```
0x71f9829000:  a9bf7bfd     stp  x29, x30, [sp, #-16]!    displaced, copied
0x71f9829004:  910003fd     mov  x29, sp                  displaced, copied
0x71f9829008:  f0000008     adrp x8, ...                  displaced, RE-ENCODED
0x71f982900c:  f944ad08     ldr  x8, [x8, #2392]          displaced, copied
0x71f9829010:  58000050     ldr  x16, #8                  jump back
0x71f9829014:  d61f0200     br   x16
0x71f9829018:  f982b724                                   .quad target+16
0x71f982901c:  00000071
```

Read the last two words together, little-endian: `0x00000071_f982b724` = `0x71f982b724`, which is
`target + 16`. Exactly the instruction after the patch.

### Step 6 — patch the target

```c
void  *pg   = PAGE_DOWN(target);
size_t span = ((uintptr_t)target + 16) - (uintptr_t)pg;
mprotect(pg, span, PROT_READ | PROT_WRITE | PROT_EXEC);
put_abs_jump((uint32_t *)target, (uintptr_t)replacement);
mprotect(pg, span, PROT_READ | PROT_EXEC);
```

**Measured on this device:** `mprotect` with `PROT_WRITE|PROT_EXEC` on the library's private,
file-backed text mapping **succeeded** for a `shell`-domain process on API 33. Do not generalise
that: SELinux policy can refuse `execmod` on a modified file-backed page, and some builds do. The
shipped example prints `mprotect RWX refused` and retries without `PROT_EXEC` when that happens,
because you do not need `W` and `X` simultaneously — you need `W` while writing and `X` afterwards.

### Step 7 — flush the instruction cache

```c
__builtin___clear_cache((char *)target, (char *)target + 16);
```

This is the step every tutorial mentions and few explain. On AArch64 the data and instruction caches
are **not coherent** with each other. Your `str` lands in the D-cache; the CPU fetches instructions
through the I-cache; nothing automatically tells the I-cache that the bytes it holds are stale. The
architecture requires an explicit sequence — clean the data cache to the point of unification,
invalidate the instruction cache, `dsb`, `isb` — and `__builtin___clear_cache` emits it (or calls
libc's `__clear_cache`, which does).

**Now the honest part.** I tried to make the omission visible and could not:

```
# cachetest: mprotect the page RWX ONCE, call the function 2,000,000 times to
# warm the I-cache, patch it with NO mprotect and NO cache maintenance, call again.

run 1 (no flush):   after patch: f("wrong") = 1   (1 = new code ran, 0 = STALE)
run 2 (no flush):   after patch: f("wrong") = 1
run 3 (with flush): after patch: f("wrong") = 1
```

On this Cortex-A53, the un-flushed patch executed correctly every time. **That does not make it
safe.** The architecture permits the CPU to execute the stale bytes; it does not require it to. A
core that had not recently fetched that line, a different microarchitecture with deeper prefetch, or
a second thread already inside the function are all cases where it would fail — and it would fail
non-deterministically, which is the worst kind of bug to own.

> **Mental Model.** Cache maintenance is not an optimisation you can skip when it seems to work.
> It is the difference between "correct" and "happened to work on the chip I tested". This lab tried
> to catch it failing, failed to, and reports both facts rather than repeating folklore in either
> direction.

---

## 6. Run it and read the proof

```bash
# host
adb push $OUT/libguard.so $OUT/trampoline-hook /data/local/tmp/
adb shell chmod 755 /data/local/tmp/trampoline-hook
adb shell /system/bin/linker64 /data/local/tmp/trampoline-hook
```

Measured, in full:

```
page size = 4096 bytes
guard_check @ 0x71f982b714

== BEFORE ==
  guard_check("wrong")        = 0
  guard_check("s3cr3t-token")  = 1
  original prologue:
    0x71f982b714:  a9bf7bfd
    0x71f982b718:  910003fd
    0x71f982b71c:  b0000008
    0x71f982b720:  f944ad08

trampoline page @ 0x71f9829000  (-10004 bytes from target)

== RELOCATING the 4 displaced instructions ==
    [copy ] a9bf7bfd  (position independent)
    [copy ] 910003fd  (position independent)
    [reloc] adrp b0000008 -> f0000008   (target page 0x71f982c000, imm 1 -> 3)
    [copy ] f944ad08  (position independent)

== AFTER ==
  patched prologue:
    0x71f982b714:  58000050
    0x71f982b718:  d61f0200
    0x71f982b71c:  8be11520
    0x71f982b720:  00000074
  guard_check("wrong")        = 1
  guard_check("s3cr3t-token")  = 1

guard_counter = 4
```

### 6.1 Three claims, three pieces of evidence

| Claim | Evidence |
|---|---|
| The hook changed behaviour | `guard_check("wrong")` was `0` before and `1` after |
| The original body still ran | `guard_counter` is `4` after four calls — only the trampoline path increments it |
| A PC-relative instruction was re-encoded, not copied | `b0000008` → `f0000008`, with the target page unchanged at `0x71f982c000` |

The second row is the one people skip, and it is the one that distinguishes a **hook** from a
**replacement**. If you had written `mov w0, #1; ret` over the prologue, `guard_check("wrong")` would
also return 1 — and `guard_counter` would read 2, because the body never executed. Always find a
side effect you can count.

### 6.2 Read the patched prologue back

```
0x71f982b71c:  8be11520
0x71f982b720:  00000074
```

Little-endian, low word first: `0x00000074_8be11520` = `0x748be11520`. That is the address of
`replacement()` in the hook binary. Those eight bytes are **data**, sitting in the middle of a code
section, executed by nothing — because `br x16` at `+4` jumps away before reaching them.

This is also, immediately, a detection surface: `0x00000074` and `0x8be11520` are not plausible
AArch64 instructions, and a self-checksum over the prologue notices instantly. Lab 04 makes a
challenge out of exactly that.

---

## 7. Exercises

### 7.1 Make it a 4-byte branch instead (moderate)

Change the patch to a single `b <replacement>` and displace only one instruction.

- Compute the `b` encoding yourself: `0x14000000 | ((offset >> 2) & 0x03FFFFFF)`, where `offset` is
  `replacement − target`. Verify your arithmetic against a round trip
  (`b .`, `b .+4`, `b .-4` assemble to `0x14000000`, `0x14000001`, `0x17ffffff` — measured).
- Add a range check. If `|offset| > 128 MiB`, refuse rather than emitting a wrong branch.
- **Question:** the only displaced instruction is now `stp x29, x30, [sp, #-16]!`, which is position
  independent. Did the relocation problem disappear?

<details>
<summary>Answer</summary>

For `guard_check`, yes — for this function, with this patch size. It has not disappeared in general.
Run the analyser on `guard_level` with `--patch-bytes 4`:

```
guard_level  @ 0x1750  (size 20 bytes)
displaced instructions:
  +0    b0000008  RELOC adrp
VERDICT: NEEDS RELOCATION
```

Its `adrp` is instruction **zero**. Even a 4-byte patch displaces it. Patch size changes *how often*
you meet the problem, never *whether* it exists.

</details>

### 7.2 Make the hook removable (moderate)

Save the four original words before patching and add an `unhook()` that restores them. Then:

- Verify `guard_check("wrong")` returns to `0`.
- **Question:** in what order must you restore the bytes and flush the cache, and what happens if
  another thread is executing inside the function while you do it?

<details>
<summary>Answer</summary>

Restore, then flush — the same order as installing. The thread question has no good answer with this
design: a thread can be *inside* the trampoline, or at any of the four patched addresses, and
restoring underneath it produces a jump to a half-restored prologue. Real engines either stop the
world, or keep the trampoline alive forever after unhooking so any thread still executing there
finishes safely. **The fact that this lab's engine cannot answer safely is the answer**: single-word
atomic patching and thread quiescence are why production hooking libraries are thousands of lines
rather than two hundred.

</details>

### 7.3 Break it deliberately (essential)

Comment out the `adrp` re-encoding so the instruction is copied verbatim, rebuild, and run.

**Predict before running:** what will `guard_counter` be after the calls, and why?

<details>
<summary>Answer</summary>

The `adrp` in the trampoline now forms the wrong page. The following `ldr x8, [x8, #2392]` loads a
pointer from an address that is not the GOT entry for `guard_counter`, and the code then writes
through it. The likely outcomes are a `SIGSEGV`, or — much worse — a *silent* write into whatever
happens to live at that address.

That is the lesson: a mis-relocated `adrp` does not produce a wrong answer you can see. It produces
memory corruption in a location unrelated to your hook, discovered later, somewhere else.

</details>

### 7.4 Hook a function whose prologue you cannot displace (hard)

Run the analyser against `libinline.so`:

```bash
python3 -B hookability.py $OUT/libinline.so --symbol lic_is_valid
```

Measured:

```
displaced instructions:
  +0    b4000120  BLOCK cbz/cbnz
        Compare-and-branch to 0x1670, range +/-1 MiB.
  +4    a9bf7bfd  copy
  +8    910003fd  copy
  +12   f0ffffe1  RELOC adrp

PROBLEMS:
  [!] displaced instruction +0 (b4000120, cbz/cbnz) cannot be relocated
VERDICT: UNSAFE
```

The very first instruction is a conditional branch. Answer:

1. Why is relocating a `cbz` harder than relocating an `adrp`, given that both are PC-relative?
2. Name two ways to hook this function anyway.

<details>
<summary>Answer</summary>

1. `adrp` computes a value; the fix is arithmetic on its immediate, and its ±4 GiB reach almost
   always survives a nearby trampoline. `cbz` transfers control, its reach is only ±1 MiB, and a
   relocated copy must still branch to the *original* target — which is usually further than 1 MiB
   from a trampoline you did not get to choose the address of. Handling it properly means emitting a
   **veneer**: rewrite `cbz x0, far` as `cbnz x0, +8 / b far`, which changes the instruction count
   and therefore every offset after it.
2. (a) Use a smaller patch — an 8-byte wholesale replacement (`mov w0,#1; ret`) needs no trampoline
   at all, because the displaced instructions are discarded rather than moved. That is what
   [`../examples/hook-that-fails.c`](../examples/hook-that-fails.c) does. (b) Hook at a *different
   address* inside the function, past the awkward prologue — legal, but you must be certain no path
   reaches the function body except through the bytes you patched.

</details>

### 7.5 The instruction that would silently corrupt everything (hard)

`hookability.py` checks whether any instruction in the function branches **into** the patch region.
Explain, concretely, what happens if one does and you patch anyway — and why this failure is worse
than a crash at install time.

<details>
<summary>Answer</summary>

Say the function has a loop whose back-edge targets `target+8`. After a 16-byte absolute-jump patch,
`target+8` is the **first four bytes of the 64-bit address literal**. When the loop iterates, the CPU
fetches those bytes and executes them as an instruction. In the measured run, `target+8` held
`0x8be11520` — which decodes to something, and that something is whatever the low half of a heap
address happens to encode.

It is worse than a crash because it is **path-dependent**. The function works perfectly until the
loop runs a second time, or until an argument takes the branch, so the failure appears far from the
hook, intermittently, and looks like an application bug rather than an instrumentation bug. You will
debug the wrong program.

</details>

---

## 8. Success criteria

- [ ] You can convert between "bytes in file" and "instruction word" in both directions, unaided.
- [ ] You can explain what `adrp` computes, and re-encode one for a new address with pencil and
      paper, matching the measured `b0000008 → f0000008`.
- [ ] Your hook prints a **counter** proving the original body executed, not just a changed return
      value.
- [ ] You can state the reach of `b` (±128 MiB), `adrp` (±4 GiB), `b.cond`/`cbz` (±1 MiB) and `tbz`
      (±32 KiB), and say why the trampoline's *address* is a constraint rather than a detail.
- [ ] You can explain why `MAP_FIXED_NOREPLACE` and not `MAP_FIXED`, and what an `mmap` hint is worth
      (measured: nothing — the kernel returned a page 10.3 GiB away).
- [ ] You can state what `__builtin___clear_cache` does and why "it worked without it on my device"
      is not evidence that it is unnecessary.
- [ ] You broke the relocation deliberately (7.3) and can describe the failure mode without running
      it again.

---

## 9. What you have actually built

Roughly 250 lines of C that does, by hand, what `Interceptor.attach()` does for you in one line. The
value is not the code — it is that from here on, when a hooking engine refuses a function, you know
what it refused and why, and when a hook installs but nothing changes, you know that the engine did
its job and the problem is somewhere else.

That "somewhere else" is [Lab 03](lab-03-where-hooks-fail.md).

---

## 10. Cleanup

```bash
# host
adb shell rm -f /data/local/tmp/libguard.so /data/local/tmp/trampoline-hook
```

Check that no binary escaped into the repository:

```bash
# host
find 65-Hooking -name '*.so' -o -name '*.o' -o -name '__pycache__'
```

It must print nothing.
