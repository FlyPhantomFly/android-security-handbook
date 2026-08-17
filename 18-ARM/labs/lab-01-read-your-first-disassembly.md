# Lab 01 — Read your first disassembly

> **Objective:** compile one C file five different ways, disassemble all five, and use the
> differences to learn something you cannot learn from any single listing — that the assembly you are
> reading is a property of the *compiler*, not of the source. By the end you will be able to open an
> unfamiliar AArch64 function and say what it returns, without a decompiler.

**Prerequisites:** [18-ARM §1–§3.10](../README.md#3-deep-internal-working);
[01-Computer-Science-Basics](../../01-Computer-Science-Basics/README.md) §hexadecimal and §endianness
**Difficulty:** Beginner — but do not skip it, everything else in this chapter assumes it
**Time:** 90–120 minutes
**You will need:** the Android NDK (r21 or newer), a shell, and Python 3. **No device.**

---

## Why this lab exists

There is a decompiler three chapters away that will turn every function in this lab into readable C
in one click. Use it *after*, not instead.

Two things only become real by doing this by hand. The first is that **compiled code has a small
vocabulary**. Almost every function you will ever read is assembled from twenty-odd recurring
phrases, and you cannot believe that until you have watched twenty-four deliberately different C
functions collapse into the same handful of shapes. The second is that **the disassembly is not the
source**. Beginners silently assume that `return a + b;` "is" `add w0, w1, w0`. It is, at `-O2`, on
one compiler. At `-O0` the same function is seven instructions and touches memory twice. Until you
have seen both, from the same file, in the same run, that assumption sits there waiting to mislead
you.

The practical payoff comes in [Lab 02](lab-02-patch-the-licence-check.md) and in real work: when a
decompiler produces nonsense — on packed code, on hand-written assembly, on a function whose
boundaries it got wrong — the only person who can say what the code does is the one who can read the
instructions.

---

## Setup

```bash
# host -- Git Bash, WSL, Linux or macOS
export ANDROID_HOME="$HOME/Android/Sdk"      # wherever your SDK lives
cd 18-ARM/examples
./build-arm-fixtures.sh /tmp/ch18
```

You should see something like this. **Write down your clang version** — you will need it in Part F.

```text
NDK bin : .../ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin
output  : /tmp/ch18
clang   : Android (9352603, based on r450784d1) clang version 14.0.7 ...
objdump :   LLVM version 14.0.7git

  libpatterns64.so             arm64, -O2, canary on
  libpatterns64-O0.so          arm64, -O0, textbook prologues
  libpatterns64-nocanary.so    arm64, -O2, canary OFF
  libpatterns32-arm.so         armeabi-v7a, ARM state
  libpatterns32-thumb.so       armeabi-v7a, Thumb state
  liblicence.so                arm64 patch target
  licence-runner               arm64 Android executable

Thumb vs ARM -- st_value for the same three functions:
  symbol                   ARM state    Thumb state
  pat_leaf_add             0x00001a60   0x00001a61
  pat_cbz                  0x00001aa8   0x00001a95
  pat_boolean_check        0x00001d8c   0x00001cad
```

> **⚠️ The output directory must be outside this repository.** Compiled binaries are build artefacts
> and this repository commits none.

Set up a shortcut for the toolchain, because you will type it a lot:

```bash
# host
NB="$ANDROID_HOME/ndk/25.2.9519653/toolchains/llvm/prebuilt/$(ls "$ANDROID_HOME/ndk/25.2.9519653/toolchains/llvm/prebuilt")/bin"
OD="$NB/llvm-objdump"
RE="$NB/llvm-readelf"
cd /tmp/ch18
```

### If you do not have the NDK

You can still do Parts A, B and D against any `arm64-v8a` library you have. Pull one off a device you
own, or extract one from an APK you are allowed to analyse:

```bash
# host
adb pull /system/lib64/libcutils.so /tmp/ch18/
# or
unzip -o some-app.apk 'lib/arm64-v8a/*' -d /tmp/ch18/
```

You will not be able to compare optimisation levels or ARM/Thumb, which is most of the value. Get the
NDK when you can — it is a download, not a build.

---

## Part A — Read four functions cold

No hints. Open the listing and answer the questions before reading on.

```bash
# host
$OD -d --no-show-raw-insn libpatterns64.so | less
```

### A1

```text
000000000000519c <pat_leaf_add>:
    519c:       add     w0, w1, w0
    51a0:       ret
```

1. How many arguments does this function take, and where are they?
2. What does it return?
3. Does it call anything? How can you tell **without** looking at the source?
4. Is its return address on the stack at any point during its execution?

### A2

```text
00000000000051fc <pat_cbz>:
    51fc:       cbz     x0, 0x5208
    5200:       ldrb    w0, [x0]
    5204:       ret
    5208:       mov     w0, #-1
    520c:       ret
```

5. There is no `cmp` here. What is being compared, and against what?
6. Why is the register `x0` on line 1 and `w0` on line 2? What does that tell you about the C types?
7. What C would produce this? Write it out.
8. `ldrb` and not `ldrsb`. What would change if it were `ldrsb`?

### A3

```text
000000000000521c <pat_cset>:
    521c:       cmp     w0, #100
    5220:       cset    w0, gt
    5224:       ret
```

9. Write the C.
10. `gt`, not `hi`. What does that tell you about the argument's type?
11. **You want this function to always return 1. Which single instruction do you change, and what do
    you change it to?**

### A4

```text
0000000000005248 <pat_string_literal>:
    5248:       adrp    x0, 0x0
    524c:       add     x0, x0, #3208
    5250:       ret
```

12. What is in `x0` when this returns — a value, or an address?
13. What is the numeric result? Show the arithmetic.
14. Find out what is actually there:

```bash
# host
$OD -s -j .rodata libpatterns64.so | head
```

15. Your `llvm-objdump` probably printed something like `adrp x0, 0x0 <pat_tbz>`. Why is
    `<pat_tbz>` there, and why must you ignore it?

<details>
<summary><strong>Answers — Part A</strong></summary>

1. Two, in `w0` and `w1` (AAPCS64: arguments one to eight in `x0`–`x7`, `w` view for 32-bit values).
2. Their sum, in `w0`, because `x0` is also the return-value register.
3. There is no `stp x29, x30, [sp, ...]`. A function that calls something must spill `x30` (the link
   register), because `bl` would overwrite it. No spill means no call. It is a **leaf function**.
4. **No.** `x30` holds it for the whole life of the function. This is a genuine difference from
   x86-64, where `call` pushes the return address onto the stack.
5. `x0` against zero. `cbz` — "compare and branch if zero" — does the comparison itself and sets no
   flags, which is why there is no `cmp`.
6. `x0` is a 64-bit pointer being tested for NULL; `w0` is the 32-bit `int` being returned. The
   register is the same storage, the width tells you the type.
7. `int f(const char *s) { if (s == NULL) return -1; return (int)s[0]; }`
8. `ldrsb` sign-extends. A byte of `0xFF` would become `-1` instead of `255`. On Android ARM, plain
   `char` is unsigned, which is why the compiler chose `ldrb`.
9. `int f(int v) { return v > 100; }`
10. `gt` is the **signed** greater-than condition, so `v` is a signed type — an `int`. An `unsigned`
    would have compiled to `hi`.
11. Replace `cset w0, gt` at `0x5220` with `mov w0, #1` — the bytes `20 00 80 52`. One instruction,
    four bytes. That is the whole of Lab 02 in one line.
12. An **address**. `adrp` + `add` forms a pointer; `adrp` + `ldr` would have loaded the contents.
13. `0x0` (the page base objdump computed) `+ 3208` = `0x0 + 0xC88` = **`0xC88`**.
14. `.rodata` at `0xC88` is `2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 75 00` — the string
    `/system/bin/su`.
15. `adrp` computes a *page base*, and objdump annotates any address with the nearest preceding
    symbol. The nearest symbol to a page base is meaningless. **Always ignore the angle-bracket
    annotation on an `adrp` line** and read the number.

</details>

---

## Part B — The catalogue, by hand

Now work through the rest of the file with [README §3.10](../README.md#310-the-pattern-catalogue)
open beside you. For each function below, find it in the listing and fill in the table.

```bash
# host -- pull out one function at a time
$OD -d --no-show-raw-insn libpatterns64.so | sed -n '/<pat_tbz>:/,/^$/p'
```

| Function | Which pattern? | The one instruction that gives it away |
|---|---|---|
| `pat_nonleaf` | | |
| `pat_callee_saved` | | |
| `pat_cmp_branch` | | |
| `pat_csel` | | |
| `pat_tbz` | | |
| `pat_global_read` | | |
| `pat_big_constant` | | |
| `pat_calls_import` | | |
| `pat_indirect_call` | | |
| `pat_switch` | | |
| `pat_inline_memcpy` | | |
| `pat_load_widths` | | |
| `pat_stack_canary` | | |
| `pat_float_args` | | |
| `pat_nine_args` | | |
| `pat_big_return` | | |
| `pat_raw_syscall` | | |
| `pat_read_thread_pointer` | | |
| `pat_loop_sum` | | |
| `pat_boolean_check` | | |

Four of these are worth stopping on.

### B1 — `pat_nonleaf`

The C is `return pat_leaf_add(a, 7) * 2;`. Find the `bl`.

**There isn't one.** Explain what happened, in one sentence. (Answer: §3.5.)

### B2 — `pat_calls_import` and `pat_tail_call`

Both are a single instruction. Why is that not a bug, and what happens to `x30`?

### B3 — `pat_switch`

```text
    52bc:       cmp     w0, #7
    52c0:       b.hi    0x52d4
```

The C has `case 0:` through `case 7:` and a `default:`. There is only **one** comparison, and it is
unsigned. What does a negative `op` do, and why is one comparison enough?

### B4 — `pat_loop_sum`

Twenty-three instructions for a four-line loop. Do **not** read it instruction by instruction.
Instead:

1. Find the guard that returns 0 for `n < 1`.
2. Find the guard that decides whether to vectorise.
3. Find the vector loop (it contains `ldp q2, q3`).
4. Find the horizontal reduction (`addv`).
5. **Find the scalar remainder loop** — four instructions near `0x5488`.

Step 5 is the point: the scalar loop is a faithful transcription of the C, and reading it answers
"what does this function do" in about ten seconds. The other nineteen instructions are the compiler
being clever, and you can skip them.

---

## Part C — The same source, five ways

This is the part you cannot get from any single listing.

### C1 — `-O2` versus `-O0`

```bash
# host
$OD -d --no-show-raw-insn libpatterns64.so    | sed -n '/<pat_leaf_add>:/,/^$/p'
$OD -d --no-show-raw-insn libpatterns64-O0.so | sed -n '/<pat_leaf_add>:/,/^$/p'
```

```text
# -O2
000000000000519c <pat_leaf_add>:
    519c:       add     w0, w1, w0
    51a0:       ret

# -O0
00000000000051bc <pat_leaf_add>:
    51bc:       sub     sp, sp, #16
    51c0:       str     w0, [sp, #12]
    51c4:       str     w1, [sp, #8]
    51c8:       ldr     w8, [sp, #12]
    51cc:       ldr     w9, [sp, #8]
    51d0:       add     w0, w8, w9
    51d4:       add     sp, sp, #16
    51d8:       ret
```

**Questions.**

16. Why does the `-O0` build spill both parameters to the stack and immediately reload them?
17. Which build would be easier to patch, and which easier to *read*? Are they the same answer?
18. Now do the same for `pat_nonleaf`. What is in the `-O0` build that is missing from `-O2`?

### C2 — canary on versus canary off

```bash
# host
$OD -d --no-show-raw-insn libpatterns64.so          | sed -n '/<pat_stack_canary>:/,/^$/p'
$OD -d --no-show-raw-insn libpatterns64-nocanary.so | sed -n '/<pat_stack_canary>:/,/^$/p'
```

19. Count the instructions in each. How many did the canary add?
20. How much bigger is the stack frame? (Look at the `sub sp, sp, #N`.)
21. Identify all five steps of the canary: read the thread pointer, load the guard, plant it, re-read
    and compare, and the failure branch.
22. **The buffer moved.** In the unprotected build the `snprintf` destination is `sp`; in the
    protected build it is `sp + 8`. Why did the compiler rearrange the frame? (Hint: what is at
    `sp + 0` now, and what would an overflow of the buffer hit first in each layout?)
23. Confirm your reading against the symbol table:

```bash
# host
$RE --dyn-syms libpatterns64.so          | grep stack_chk
$RE --dyn-syms libpatterns64-nocanary.so | grep stack_chk
```

### C3 — ARM state versus Thumb state

```bash
# host
$OD -d libpatterns32-arm.so   | sed -n '/<pat_leaf_add>:/,/^$/p'
$OD -d libpatterns32-thumb.so | sed -n '/<pat_leaf_add>:/,/^$/p'
$OD -d libpatterns32-thumb.so | sed -n '/<pat_cbz>:/,/^$/p'
```

24. How many bytes is `pat_leaf_add` in each?
25. In the Thumb build, `add r0, r1` has two operands where the ARM build has three. What does that
    imply about where the result goes, and why is that acceptable in a 16-bit encoding?
26. In Thumb `pat_cbz` you will see `ite ne`. What is it, and what does AArch64 use instead?
27. Find one 4-byte instruction in a Thumb listing. How did you know it was 4 bytes?

### C4 — the Thumb bit

```bash
# host
$RE --dyn-syms libpatterns32-thumb.so | egrep 'pat_leaf_add|pat_boolean_check'
$OD -d libpatterns32-thumb.so | grep -A1 '<pat_boolean_check>:'
```

28. `readelf` says `pat_boolean_check` is at `0x1cad`. `objdump` puts the code at `0x1cac`. **Which
    is wrong?**
29. If you wanted to patch that function, which address would you convert to a file offset?
30. If you wanted to *call* it through a function pointer, which value would you use?

<details>
<summary><strong>Answers — Part C</strong></summary>

16. At `-O0` the compiler is required to keep every variable in its declared storage so that a
    debugger can see it and modify it between any two statements. Registers are an optimisation it is
    not allowed to make.
17. **Not the same answer.** `-O0` is far easier to *read* — every C statement maps to a contiguous
    group of instructions. `-O2` is often easier to *patch*, because a check collapses into a single
    `cset` you can overwrite, whereas at `-O0` the same logic may be spread over a dozen
    instructions with the result round-tripped through memory.
18. A real `bl pat_leaf_add@plt`. At `-O2` it was inlined and then constant-folded, so `(a+7)*2`
    became `a*2 + 14` — `lsl w8, w0, #1` followed by `add w0, w8, #14`.
19. Five: `mrs`, `ldr`, `stur`, `ldr`+`ldur`+`cmp`+`b.ne` at the end (four), and the `bl
    __stack_chk_fail`. Count them yourself; the exact number depends on how you attribute the extra
    `str x19` / `ldr x19` pair the canary forced.
20. `sub sp, sp, #80` versus `sub sp, sp, #112` — 32 bytes more, for an 8-byte canary plus a saved
    `x19` plus alignment padding.
21. `mrs x19, TPIDR_EL0`; `ldr x8, [x19, #40]`; `stur x8, [x29, #-8]`; `ldr x8, [x19,#40]` /
    `ldur x9, [x29,#-8]` / `cmp x8, x9` / `b.ne`; `bl __stack_chk_fail@plt`.
22. `-fstack-protector-strong` moves **arrays above scalars** in the frame. If a scalar (say, a
    pointer or a length) sat above the array, an overflow would corrupt it *before* reaching the
    canary, and the canary check would never fire. Putting arrays highest means a linear overflow
    hits the canary first.
28. **Neither.** `st_value` carries the Thumb state in bit 0; the address is `0x1cac` and the `1`
    says "enter Thumb". Both tools are reporting exactly what is in the file.
29. `0x1cac` — clear the low bit first.
30. `0x1cad` — keep it, because `bx` needs it to switch state.

</details>

---

## Part D — Read a real check

Now the one that matters. Open the patch target.

```bash
# host
$OD -d liblicence.so | sed -n '/<lc_verify_signature>:/,/^$/p'
```

Work through it with the catalogue:

31. Instruction 1 to 4: what is the prologue doing, and how big is the frame?
32. `mrs x20, TPIDR_EL0` at `0x48e0`. What is about to happen, and why is `x20` (a callee-saved
    register) the right choice?
33. `cbz x0, 0x498c`. What is being checked?
34. `bl 0x4bd0 <strlen@plt>` then `cmp x0, #17`. What did the C say?
35. Three `cmp` instructions against `#65`, `#82`, `#77`. What are those in ASCII?
36. Then a block with no calls at all, containing `mov`/`movk` pairs, `eor`, `orr` and
    `cmp x8, #0`. **What library function was inlined here?** How do you know?
37. **Recover the full expected token** from the `movz`/`movk` immediates. Work it out before
    checking. The method is in [README §3.10 pattern 24](../README.md#310-the-pattern-catalogue), but
    try first:
    - each `movk Xd, #imm, lsl #S` places `imm` at bit position `S`;
    - assemble the full 64-bit value;
    - write out its bytes **little-endian** (lowest byte first);
    - read them as ASCII.
38. Verify:

```bash
# host
$OD -s -j .rodata liblicence.so
```

39. The token is *also* in `.rodata`. Does that mean step 37 was wasted effort? (Think about what
    happens when a developer builds with the comparison inlined but the string not otherwise used, or
    when the constant is a key rather than a string.)

---

## Part E — Prove you can do it unaided

Pick a library you did not build. `/system/lib64/libcutils.so` off a device, or any `arm64-v8a`
library from an APK you are allowed to analyse.

```bash
# host
$RE --dyn-syms -W target.so | grep ' FUNC ' | head -30
$OD -d --no-show-raw-insn target.so | sed -n '/<some_function>:/,/^$/p'
```

For any three functions, write down:

- how many arguments it takes (count which of `x0`–`x7` are *read* before being written);
- whether it is a leaf;
- what it calls;
- whether it returns a boolean, and if so, which instruction produces it;
- one thing you cannot determine from the disassembly alone.

That last bullet is the most important. AAPCS64 tells you **where** arguments are; it never tells you
**what** they are. `x1` holding `17` might be a length, an enum, a file descriptor, or a pointer that
happens to be small.

---

## Part F — Reproducibility

40. Run `$OD --version` and `$NB/aarch64-linux-android21-clang --version`. Write both down.
41. Compare three of your addresses against the chapter's. Do they match?
42. If they do not, is the chapter wrong, are you wrong, or is neither?
43. What *should* match regardless of toolchain, and what should not?

<details>
<summary><strong>Answers — Part F</strong></summary>

40–42. Neither is wrong. The chapter states its toolchain (NDK 25.2.9519653, clang 14.0.7, API 21)
precisely so that a divergence is attributable. Register allocation, instruction scheduling and
inlining decisions change between clang releases, and any change in code size shifts every
subsequent address.

43. **Shapes** should match: `pat_cset` should still be `cmp` / `cset` / `ret`; `pat_string_literal`
should still be `adrp` / `add` / `ret`; the canary should still be `mrs` / `ldr` / `stur`. Addresses,
exact register numbers, and the ordering of independent instructions should **not** be expected to
match.

</details>

---

## Success criteria

You are done when you can, without notes:

- [ ] Say where the first eight integer arguments live, and where the ninth goes.
- [ ] Recognise a leaf function in under a second, and say why its return address is not on the
      stack.
- [ ] Explain the difference between `adrp`+`add` and `adrp`+`ldr`, and compute an `adrp`+`add`
      target from a listing.
- [ ] Point at the instruction in a three-instruction check that produces the boolean, and say what
      four bytes you would replace it with.
- [ ] Identify a canary prologue from `mrs Xn, TPIDR_EL0` alone, and say where the guard comes from.
- [ ] Recover a string constant from a `movz`/`movk` chain, by hand.
- [ ] State three things that change between `-O0` and `-O2` on the same source.
- [ ] Explain why `st_value` is odd for a Thumb function and what to do about it.
- [ ] Say one thing a disassembly can never tell you.

---

## Where next

- [Lab 02 — Patch the licence check](lab-02-patch-the-licence-check.md) turns question 11 of Part A
  into four bytes on disk, and then shows you the case where the same technique changes nothing.
- [Lab 03 — Runtime truth](lab-03-runtime-truth.md) does all of this against a live process, where
  the file and memory can disagree.
- [Lab 04 — CTF](lab-04-ctf-four-decisions.md) gives you a stripped binary and four flags, with no
  source, no symbols beyond four exports, and no decompiler.
- [57-Ghidra](../../57-Ghidra/README.md) is the tool you have now earned the right to use.
