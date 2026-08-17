# Lab 02 — Patch the licence check

> **Objective:** change a program's behaviour by editing four bytes of a shared library, and prove
> you changed it three independent ways. Then do the same thing to a second function, watch it
> demonstrably return the value you forced, and discover that nothing else changed — because the
> check that actually ran was somewhere else entirely. That second half is the lab.

**Prerequisites:** [Lab 01](lab-01-read-your-first-disassembly.md);
[18-ARM §2.4](../README.md#24-the-one-arithmetic-fact-everything-depends-on),
[§3.9](../README.md#39-deciding-without-branching-cset-csel-csinc),
[§5.4](../README.md#54-the-worked-example-what-patching-a-check-actually-buys-you),
[§6.6](../README.md#66-the-address-arithmetic-and-the-mistakes-that-come-from-it)
**Difficulty:** Intermediate
**Time:** 2–3 hours
**You will need:** the NDK and Python 3. An arm64 device or emulator is **optional** but is where
Part E happens, and Part E is the point.

---

## Why this lab exists

Almost every published "crack" of a mobile app comes down to what you are about to do: find the
instruction that produces a boolean, overwrite it, and ship the result. It takes four bytes and about
ninety seconds once you know where to look.

That is the easy half, and it is not why this lab is three hours long.

The hard half is knowing **when it works**. A patch that changes bytes is trivial to verify. A patch
that changes *behaviour* is not, and the two are not the same thing. This lab walks you through three
patches on the same library: one that works completely, one that works perfectly and accomplishes
absolutely nothing, and one that works and still leaves you empty-handed. Understanding why each
turned out the way it did is the difference between someone who can run a patching tool and someone
who can write an honest finding.

---

## Setup

```bash
# host
export ANDROID_HOME="$HOME/Android/Sdk"
cd 18-ARM/examples
./build-arm-fixtures.sh /tmp/ch18

cd /tmp/ch18
NB="$ANDROID_HOME/ndk/25.2.9519653/toolchains/llvm/prebuilt/$(ls "$ANDROID_HOME/ndk/25.2.9519653/toolchains/llvm/prebuilt")/bin"
OD="$NB/llvm-objdump"
S="$OLDPWD/../scripts"      # adjust to wherever 18-ARM/scripts is
```

**Work on copies.** Every patch below gets its own file so you can compare them at the end:

```bash
# host
cp liblicence.so lic-A.so     # Part C: lc_is_licensed
cp liblicence.so lic-B.so     # Part D: lc_verify_signature
cp liblicence.so lic-C.so     # Part F: lc_decrypt_flag
```

### The target

[`examples/licence-check.c`](../examples/licence-check.c) ships four functions of deliberately
escalating patch difficulty. You have read `lc_verify_signature` already in Lab 01 Part D.

| Function | What it does | Patch difficulty |
|---|---|---|
| `lc_is_licensed(int tier)` | `return tier >= 2;` | One instruction |
| `lc_verify_signature(const char *token)` | Several checks feeding one boolean | Two instructions — and see Part D |
| `lc_is_device_rooted(void)` | A loop over five suspect paths | Easy result, instructive loop |
| `lc_decrypt_flag(token, out, n)` | **The check gates a computation** | See Part F |

You may read the C. You will get much more out of the lab if you do not, until Part G.

---

## Part A — Triage

Never start by reading a library front to back.

```bash
# host
python3 "$S/find-check-shapes.py" liblicence.so
```

```text
liblicence.so -- 5 candidate check-shaped functions (score >= 3)
Shape score only. Nothing here is a finding; it is a reading list.

========================================================================
lc_verify_signature                       0x000048d0  224 bytes  score 10
   - cset at +0xb0 (the boolean is produced here)
   - returns a literal boolean on at least one path
   - calls strlen (length check)
   - compares against 65 ('A') at +0x4c -- a literal character test
   - 6 conditional branches -- several checks feeding one answer
   - name contains 'verify'
...
```

1. Five candidates come back. Which one would you read first, and why *not* the highest-scoring one?
2. The script scored `lc_is_licensed` at 7 with only three signals. Which three?
3. It scored `lc_decrypt_flag` at only 4, despite that being the function with the actual secret in
   it. What did the shape score fail to notice? (You will find out for certain in Part F.)
4. Run it with `--show` and `--min-score 3`. Which candidate would you reject immediately if this
   were a real library, and on what grounds?

> **⚠️ A score is not a finding.** The script says so in its own output. A boolean-returning
> `isEmpty()` has exactly the shape of a licence check. The score tells you what to *read*.

---

## Part B — The address arithmetic

Before touching anything, get the three numbers straight.

```bash
# host
python3 "$S/arm64-patch.py" liblicence.so --list-symbols
python3 "$S/arm64-patch.py" liblicence.so --symbol lc_is_licensed --show --context 3
```

```text
symbol   : lc_is_licensed  (from .dynsym)
arch     : aarch64 (ELF64)
vaddr    : 0x48c4
file off : 0x8c4   (segment vaddr 0x4874 -> offset 0x874, delta -0x4000)
size     : 12 bytes (3 instructions)

BEFORE
  000048b8: 00 50 22 91       add   x0, x0, #2196
  000048bc: 42 40 30 91       add   x2, x2, #3088
  000048c0: c0 00 00 14       b     0x4bc0
  000048c4: 1f 04 00 71   <-- cmp   w0, #1
  000048c8: e0 d7 9f 1a       cset  w0, gt
  000048cc: c0 03 5f d6       ret
  000048d0: ff 83 01 d1       sub   sp, sp, #96
```

5. The virtual address is `0x48c4` and the file offset is `0x8c4`. Where did the `0x4000` come from?
   Confirm it yourself:

```bash
# host
$NB/llvm-readelf -l liblicence.so | sed -n '/Program Headers/,/Section to/p'
```

6. `.rodata` is at virtual address `0x660`. What is *its* file offset? Is the delta the same?
7. **What would happen if you opened `liblicence.so` in a hex editor, seeked to `0x48c4`, and wrote
   four bytes?** Work out which section you would land in.
8. Ghidra would show this function at `0x001048c4`. Why, and what do you subtract?
9. At runtime the module is mapped at, say, `0x7b3c040000`. What address does Frida report for
   `lc_is_licensed`?

<details>
<summary><strong>Answers — Part B</strong></summary>

5. The second `PT_LOAD` segment has `p_vaddr = 0x4874` and `p_offset = 0x874`, so
   `vaddr - 0x4874 + 0x874 = vaddr - 0x4000`.
6. `.rodata` at virtual address `0x660` is at file offset `0x660` — it is in the **first** `PT_LOAD`,
   whose delta is **zero**. The delta is per-segment; assuming one delta for the whole file is a real
   and destructive bug.
7. `0x48c4` as a file offset is well past `.rodata` (which ends around `0x6e5`) and inside `.text`
   region on disk only by coincidence of size — in this particular file, offset `0x48c4` is past the
   end of the 6,968-byte file entirely, so a hex editor would either refuse or extend the file. In a
   larger library it would land in the middle of real data, silently.
8. Ghidra's default image base for a shared object is `0x00100000`. Subtract it, or set the image
   base to 0 in Window → Memory Map.
9. `0x7b3c040000 + 0x48c4 = 0x7b3c0448c4`.

</details>

---

## Part C — The one-instruction patch

```text
00000000000048c4 <lc_is_licensed>:
    48c4: 1f 04 00 71   cmp     w0, #1
    48c8: e0 d7 9f 1a   cset    w0, gt
    48cc: c0 03 5f d6   ret
```

10. The C is `return tier >= 2;`. Why does the compiled comparison say `#1` and not `#2`?
11. Which instruction produces the answer?
12. **Why is patching at `+0` wrong?** Predict what would happen if you overwrote the `cmp`.

### C1 — Dry run first, always

```bash
# host
python3 "$S/arm64-patch.py" lic-A.so --symbol lc_is_licensed \
        --skip 1 --patch "mov w0,#1" --context 2 --dry-run
```

```text
PATCH    : mov w0,#1
  0x000048c8  word 0x52800020  bytes 20 00 80 52  -> mov   w0, #1

AFTER
  000048c0: c0 00 00 14       b     0x4bc0
  000048c4: 1f 04 00 71       cmp   w0, #1
  000048c8: 20 00 80 52   <-- mov   w0, #1
  000048cc: c0 03 5f d6       ret

nothing written. Add --write to apply, and read the AFTER block above first.
```

13. Where did `20 00 80 52` come from? Verify it independently:

```bash
# host
python3 "$S/arm64-patch.py" --show-encodings | grep -i 'mov w0, #1'
```

14. Compute `0x52800020` yourself from the rule in [README §3.3](../README.md#33-instruction-encoding-what-a-4-byte-word-actually-contains):
    `mov wN, #imm` = `0x52800000 | (imm << 5) | N`.
15. The `cmp` is now dead — its flags are computed and never read. Is that a problem? Would replacing
    it with `nop` be better, worse, or the same?

### C2 — Apply it

```bash
# host
python3 "$S/arm64-patch.py" lic-A.so --symbol lc_is_licensed \
        --skip 1 --patch "mov w0,#1" --context 2 --write
```

```text
backup   : lic-A.so.bak
written  : 4 bytes at file offset 0x8c8
```

### C3 — Verify with a different tool

The patcher telling you it wrote the bytes is not verification; it is a claim. Check it with
something that has no idea a patch happened:

```bash
# host
$OD -d --start-address=0x48c4 --stop-address=0x48d0 lic-A.so
$OD -d --start-address=0x48c4 --stop-address=0x48d0 liblicence.so    # the pristine copy
```

```text
# patched
00000000000048c4 <lc_is_licensed>:
    48c4: 1f 04 00 71   cmp     w0, #1
    48c8: 20 00 80 52   mov     w0, #1
    48cc: c0 03 5f d6   ret

# pristine
00000000000048c4 <lc_is_licensed>:
    48c4: 1f 04 00 71   cmp     w0, #1
    48c8: e0 d7 9f 1a   cset    w0, gt
    48cc: c0 03 5f d6   ret
```

16. Confirm with a byte-level diff that **exactly four bytes** changed and that they are at `0x8c8`:

```bash
# host
cmp -l liblicence.so lic-A.so
```

`cmp -l` prints 1-based decimal offsets. `0x8c8` is 2248, so expect offsets 2249–2252.

---

## Part D — The same technique on a bigger function, and the trap

`lc_verify_signature` is 224 bytes with a stack canary. You could find its `cset` at `0x4980` and
overwrite that, but there is a blunter approach: **return immediately from the top.**

```text
00000000000048d0 <lc_verify_signature>:
    48d0: ff 83 01 d1   sub     sp, sp, #96
    48d4: fd 7b 04 a9   stp     x29, x30, [sp, #64]
```

17. Why is it safe to overwrite the *first two* instructions with `mov w0, #1` / `ret`? What would
    make it unsafe? (Think about what has and has not been pushed at that point.)
18. What would go wrong if you tried the same trick at `+8`, after `stp x29, x30, [sp, #64]`?

```bash
# host
python3 "$S/arm64-patch.py" lic-B.so --symbol lc_verify_signature \
        --patch "mov w0,#1" --patch ret --context 2 --write
```

```text
PATCH    : mov w0,#1 ; ret
  0x000048d0  word 0x52800020  bytes 20 00 80 52  -> mov   w0, #1
  0x000048d4  word 0xd65f03c0  bytes c0 03 5f d6  -> ret
written  : 8 bytes at file offset 0x8d0
```

```bash
# host
$OD -d --start-address=0x48d0 --stop-address=0x48e0 lic-B.so
```

```text
00000000000048d0 <lc_verify_signature>:
    48d0: 20 00 80 52   mov     w0, #1
    48d4: c0 03 5f d6   ret
    48d8: fd 03 01 91   add     x29, sp, #64      <-- orphaned remains of the old prologue
    48dc: f4 4f 05 a9   stp     x20, x19, [sp, #80]
```

19. Instructions `0x48d8` onward are now unreachable. Does that matter? Should you `nop` them out?
20. Before running anything, **predict**: with this patch in place and a wrong token, what will
    `lc_decrypt_flag` do? Write your prediction down. The C source says:

```c
if (!lc_verify_signature(token)) {
    return -1;
}
```

---

## Part E — Prove it at runtime

A disassembly diff proves the bytes changed. It does not prove the program does anything different.
This is the step that separates the two.

### E1 — Push everything

```bash
# host
adb push licence-runner liblicence.so lic-A.so lic-B.so /data/local/tmp/
adb shell chmod 755 /data/local/tmp/licence-runner
```

### E2 — Baseline

```bash
# host
adb shell /data/local/tmp/licence-runner /data/local/tmp/liblicence.so
```

```text
library            : /data/local/tmp/liblicence.so
token              : WRONG-TOKEN-HERE
lc_is_licensed(0)  : 0
lc_is_licensed(1)  : 0
lc_is_licensed(2)  : 1
lc_verify_signature: 0
lc_is_device_rooted: 0
lc_decrypt_flag    : refused (-1)
```

```bash
# host -- with the token you recovered in Lab 01 Part D
adb shell /data/local/tmp/licence-runner /data/local/tmp/liblicence.so ARM64-IS-NOT-HARD
```

```text
lc_verify_signature: 1
lc_decrypt_flag    : ANDROID-ARM64-FLAG
```

> **⚠️ If the runner will not execute**
> Some OEM builds block `execve` on `/data`, even for the shell user with correct permissions. The
> symptom is one of:
> ```text
> /system/bin/sh: /data/local/tmp/licence-runner: No such device or address
> /system/bin/sh: /data/local/tmp/licence-runner: Interrupted system call
> ```
> This is **not** a build problem — copy `/system/bin/toybox` to the same directory and it will fail
> the same way. Invoke the dynamic linker explicitly and let it load your executable:
> ```bash
> adb shell /system/bin/linker64 /data/local/tmp/licence-runner /data/local/tmp/liblicence.so
> ```
> That works because the thing being executed lives on a partition the policy allows. Every command
> below works with either form; use whichever your device accepts.

### E3 — Patch A

```bash
# host
adb shell /data/local/tmp/licence-runner /data/local/tmp/lic-A.so
```

```text
lc_is_licensed(0)  : 1        <-- was 0
lc_is_licensed(1)  : 1        <-- was 0
lc_is_licensed(2)  : 1
```

**Four bytes.** The tier check now always says yes, on a real device, in a real process.

### E4 — Patch B, and the surprise

```bash
# host
adb shell /data/local/tmp/licence-runner /data/local/tmp/lic-B.so
```

```text
library            : /data/local/tmp/lic-B.so
token              : WRONG-TOKEN-HERE
lc_is_licensed(0)  : 0
lc_is_licensed(1)  : 0
lc_is_licensed(2)  : 1
lc_verify_signature: 1        <-- the patch worked
lc_is_device_rooted: 0
lc_decrypt_flag    : refused (-1)   <-- and nothing else changed
```

21. Compare this against your prediction from question 20.
22. `lc_verify_signature` is *observably* returning 1. `lc_decrypt_flag`'s source calls it. Why did
    it not see the patched answer?

### E5 — Find out for certain

```bash
# host
$OD -d liblicence.so | sed -n '/<lc_decrypt_flag>:/,/^$/p' | head -40
```

23. Search that listing for `bl` instructions. List every one, with its target.
24. Is `lc_verify_signature` among them?
25. Find, inside `lc_decrypt_flag`, each of these:
    - its own `bl strlen@plt`
    - its own `cmp x0, #17`
    - its own three character comparisons against `#65`, `#82`, `#77`
    - its own `movz`/`movk` chain building `ARM64-IS` and `-NOT-HAR`
    - its own decision, at `0x4af4`

26. **In one sentence, what did the compiler do?**

<details>
<summary><strong>Answers — E5</strong></summary>

23–24. The only `bl` targets in `lc_decrypt_flag` are `strlen@plt` and `__stack_chk_fail@plt`. There
is **no** call to `lc_verify_signature`.

25–26. At `-O2` clang **inlined the whole of `lc_verify_signature` into `lc_decrypt_flag`.** There
are now two independent copies of the check in the library. The exported standalone copy survives
only because it is exported and the linker cannot prove nothing needs it — and in this program,
nothing does, except the runner calling it directly.

**This is the single most common reason a patch "does not work".** The symptom is exactly what you
just saw: the patched function demonstrably returns the new value, and the behaviour is unchanged.

</details>

---

## Part F — Patch the copy that actually runs

The decision inside `lc_decrypt_flag` starts with its own length check:

```text
    4a70: 58 00 00 94   bl      0x4bd0 <strlen@plt>
    4a74: 1f 44 00 f1   cmp     x0, #17
    4a78: 01 04 00 54   b.ne    0x4af8               <-- "refused"
    ...
    4af4: 68 01 00 b4   cbz     x8, 0x4b20           <-- success path
    4af8: 00 00 80 12   mov     w0, #-1
```

27. There are five separate ways to get to `0x4af8` ("refused"). Rather than neutralise all five,
    find the **one** instruction you could replace to skip straight to the success path at `0x4b20`.
28. Compute the branch encoding by hand before running the tool:
    `b <target>` = `0x14000000 | (((target - here) / 4) & 0x03FFFFFF)`. Here is `0x4a74`; the target
    is `0x4b20`.

```bash
# host
python3 "$S/arm64-patch.py" lic-C.so --vaddr 0x4a74 --patch "b 0x4b20" --context 2 --write
```

```text
PATCH    : b 0x4b20
  0x00004a74  word 0x1400002b  bytes 2b 00 00 14  -> b     0x4b20
written  : 4 bytes at file offset 0xa74
```

29. Does `0x1400002b` match what you computed?

```bash
# host
$OD -d --start-address=0x4a70 --stop-address=0x4a80 lic-C.so
adb push lic-C.so /data/local/tmp/
adb shell /data/local/tmp/licence-runner /data/local/tmp/lic-C.so
adb shell /data/local/tmp/licence-runner /data/local/tmp/lic-C.so ARM64-IS-NOT-HARD
```

```text
# wrong token
lc_decrypt_flag    : WNF*<IY1'YLOQ U[Q

# correct token
lc_decrypt_flag    : ANDROID-ARM64-FLAG
```

30. The gate is open — the function now runs to completion with any token. **So why is the output
    still garbage?**
31. Read this line from the source and answer again:

```c
out[i] = (char)(ct[i] ^ (unsigned char)token[i % 17]);
```

32. Is there *any* four-byte patch to this library that would make it print the flag with a wrong
    token? Argue your answer. (Consider: where is the plaintext? Where is the key?)

<details>
<summary><strong>Answers — Part F</strong></summary>

27. Replace the `cmp x0, #17` at `0x4a74` with `b 0x4b20`. Every subsequent check is downstream of
    it, so one branch skips them all. `x19`, `x20` and `x21` were already loaded with the output
    pointer, token pointer and length before `strlen` was called, so the success path has everything
    it needs.

28. `(0x4b20 - 0x4a74) / 4 = 0xAC / 4 = 0x2B`, so `0x14000000 | 0x2B = 0x1400002B`. In the file,
    little-endian: `2b 00 00 14`.

30–32. **No such patch exists**, short of writing the plaintext into the binary yourself. The
ciphertext is in `.rodata` at `0x6d3`, but the key is the *token*, which is user input. The check was
not merely gating the computation; the thing being checked was also the thing the computation needs.
That is the difference between an authorisation decision (patchable) and a cryptographic dependency
(not).

You *could*, of course, recover the flag: you already extracted the token in Lab 01 by reading the
`movk` chain, and with the correct token the pristine library prints it. The point is that the patch
did not get it for you — the analysis did.

</details>

---

## Part G — Write the finding

Now read [`examples/licence-check.c`](../examples/licence-check.c). Then write, in prose, a finding
you would be willing to put in front of a client.

It must state:

- What you changed, at which offset, and what the four bytes were.
- How you verified it — all three ways.
- Which of the three patches achieved something, and which did not.
- **Why** patch B achieved nothing, in one sentence that a developer would understand.
- What patch C did and did not get you.
- What a developer should do about it, as a concrete change — not "add obfuscation".
- What still protects the application even with all three patches in place.

A weak version of this reads "bypassed the licence check". A strong version distinguishes the tier
check (genuinely bypassed), the signature check (bypassed in the exported copy only, with the
inlined copy still governing the code path that matters), and the flag derivation (not bypassable,
because the token is the key).

---

## Stretch goals

### S1 — Patch the root check

`lc_is_device_rooted` loops over five paths. Patch it two different ways:

```bash
# host
cp liblicence.so lic-D.so
python3 "$S/arm64-patch.py" lic-D.so --symbol lc_is_device_rooted \
        --patch "mov w0,#0" --patch ret --write
```

Then do it *without* touching the function's entry: find the `mov w0, #1` at `0x4a34` that produces
the positive answer, and change it to `mov w0, #0`. Which patch would be harder for a tamper check to
spot, and why?

### S2 — Patch the JNI wrapper instead

```text
0000000000004b84 <Java_com_example_arm_Native_isLicensed>:
    4b84: 5f 04 00 71   cmp     w2, #1
    4b88: e0 d7 9f 1a   cset    w0, gt
    4b8c: c0 03 5f d6   ret
```

Why is the comparison on `w2` here and `w0` in `lc_is_licensed`? Patch it. Then explain why patching
this function and patching `lc_is_licensed` are two different patches with two different blast
radii — and note that the compiler inlined `lc_is_licensed` here too.

### S3 — Break something on purpose

Patch `lc_verify_signature` at `+8` — *after* the `stp x29, x30, [sp, #64]` — with
`mov w0,#1` / `ret`, push it, and run it. Describe exactly what happens and why. This is the fastest
way to internalise what a prologue is for.

```bash
# host
cp liblicence.so lic-E.so
python3 "$S/arm64-patch.py" lic-E.so --symbol lc_verify_signature --skip 2 \
        --patch "mov w0,#1" --patch ret --write
```

### S4 — Restore from the backup

Every `--write` made a `.bak`. Restore `lic-A.so` and confirm with `cmp` that it is byte-identical to
`liblicence.so`. Then answer: why does the tool refuse to overwrite an existing `.bak`?

---

## Success criteria

- [ ] You can state the difference between a virtual address, a file offset and a runtime address,
      and compute each from the others.
- [ ] You applied a four-byte patch and verified it with `arm64-patch.py`, with `llvm-objdump`, and
      by running the program.
- [ ] You can explain why `--skip 1` was necessary for `lc_is_licensed`.
- [ ] You computed at least one instruction encoding by hand and it matched the tool.
- [ ] You patched `lc_verify_signature`, watched it return 1, and can explain in one sentence why
      `lc_decrypt_flag` was unaffected.
- [ ] You found the inlined copy in the disassembly and can point at its `bl strlen`, its `cmp #17`
      and its own `movk` chain.
- [ ] You can explain why forcing `lc_decrypt_flag`'s gate open produced garbage.
- [ ] You wrote a finding that distinguishes "the bytes changed" from "the behaviour changed" from
      "the protection is defeated".

---

## Where next

- [Lab 03 — Runtime truth](lab-03-runtime-truth.md): the same patches, in memory, where the file and
  the process can disagree — and where an in-memory patch survives an integrity check that a file
  patch does not.
- [Lab 04 — CTF](lab-04-ctf-four-decisions.md): a stripped binary, four flags, no source.
- [38-TamperDetection](../../38-TamperDetection/README.md): what an app can do to notice everything you just did.
- [57-Ghidra](../../57-Ghidra/README.md): the decompiler, which would have shown you the inlining in
  Part D in about two seconds — and which is exactly why you did it by hand first.
