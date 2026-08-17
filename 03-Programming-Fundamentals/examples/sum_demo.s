// =================================================================================================
// sum_demo.s — the chapter's reference program at the level the CPU actually works at.
//
// PURPOSE
//   Version 4 of 4. Compare against sum_demo.py, sum_demo.c and SumDemo.java.
//   This is simplified, teaching-oriented AArch64 (ARM64) — the architecture of essentially
//   every Android device you will meet.
//
//   THIS FILE IS FOR READING, NOT FOR ASSEMBLING. It is written for clarity, with one idea per
//   line. Real compiler output is messier: it saves registers you did not ask it to save, uses
//   the frame pointer in ways that look redundant at -O0, and at -O2 may not resemble this at all.
//
// COMPARE IT WITH THE REAL THING — this is the point of the file
//   host $ gcc -O0 -S sum_demo.c -o /tmp/real_O0.s   && cat /tmp/real_O0.s
//   host $ gcc -O2 -S sum_demo.c -o /tmp/real_O2.s   && cat /tmp/real_O2.s
//   host $ diff /tmp/real_O0.s /tmp/real_O2.s
//
//   On an x86-64 host you will get x86 assembly rather than AArch64. To see ARM64:
//   host $ aarch64-linux-gnu-gcc -O0 -S sum_demo.c -o /tmp/arm.s
//   or paste sum_demo.c into https://godbolt.org/ and select an AArch64 compiler.
//
// Chapter 03 — Programming Fundamentals, sections 2.3, 3.6.2, 3.7.3, 3.8.2 and 9.1
// =================================================================================================


// -------------------------------------------------------------------------------------------------
// REGISTERS — the sixteen bytes of vocabulary you need before reading anything below
//
//   x0 .. x30   64-bit general-purpose registers
//   w0 .. w30   the LOW 32 BITS of the same registers. `w` for word, `x` for extended.
//               Writing to a w register zeroes the top 32 bits of its x counterpart.
//   sp          stack pointer — points at the top of the current stack frame
//   lr (x30)    link register — holds the RETURN ADDRESS after a `bl`
//   pc          program counter — the address of the instruction being executed
//   xzr / wzr   the zero register: reads as 0, writes are discarded
//
// THE CALLING CONVENTION (AAPCS64) — memorise this, you will use it constantly
//
//   x0..x7      the first eight integer/pointer ARGUMENTS, in order
//   x0          also the RETURN VALUE
//   x9..x15     caller-saved scratch — a callee may destroy these freely
//   x19..x28    callee-saved — a callee must preserve these across the call
//   x29 (fp)    frame pointer
//   x30 (lr)    return address
//
//   So for `int bounded_sum(int n, int limit)`:  n arrives in w0, limit arrives in w1,
//   and the result leaves in w0. That mapping is why reversing native code starts with
//   "what is in w0?".
// -------------------------------------------------------------------------------------------------


// -------------------------------------------------------------------------------------------------
// int bounded_sum(int n, int limit)
//
//   in:   w0 = n
//         w1 = limit
//   uses: w2 = total     (chosen freely; a real compiler picks differently)
//         w3 = i
//   out:  w0 = the sum, or -1
//
// Note that there is NO stack frame at all here. This function calls nothing else, so it needs
// no saved return address beyond the one already in lr, and all its locals fit in registers.
// That is a "leaf function", and recognising one saves you time when reversing.
// -------------------------------------------------------------------------------------------------
bounded_sum:
        mov     w2, #0              // total = 0                    <- int total = 0;
        mov     w3, #1              // i = 1                        <- int i = 1;

loop_test:
        // ---- the loop condition:  i <= n ? -----------------------------------------------------
        // `cmp` is a subtraction that discards its result and keeps only the flags.
        // The following branch reads those flags. This two-instruction pair IS an `if`.
        cmp     w3, w0              // compute i - n, set the condition flags
        b.gt    done_ok             // if i > n, leave the loop (the FORWARD branch)

        // ---- the loop body ---------------------------------------------------------------------
        add     w2, w2, w3          // total = total + i            <- total = total + i;
                                    // NOTE: 32-bit add. It WRAPS at 2147483647 with no signal.
                                    // Chapter 03 section 3.4 is entirely about this instruction.

        // ---- the inner conditional:  total > limit ? -------------------------------------------
        cmp     w2, w1              // compute total - limit, set flags
        b.le    loop_next           // if total <= limit, skip the early return
        mov     w0, #-1             // else return value = -1       <- return -1;
        ret                         // and return immediately (branch to the address in lr)

loop_next:
        add     w3, w3, #1          // i = i + 1                    <- the i++ of the for loop
        b       loop_test           // repeat (the BACKWARD branch)

done_ok:
        mov     w0, w2              // return value = total         <- return total;
        ret                         // branch to lr


// -------------------------------------------------------------------------------------------------
// int main(void)
//
// This one DOES need a stack frame, because it calls other functions and therefore must preserve
// its own return address — `bl` overwrites lr, so main's own lr must be saved first.
//
// The prologue/epilogue pair below is the single most recognisable shape in AArch64 reversing.
// When you are scrolling through a disassembly looking for function boundaries, this is what you
// are looking for.
// -------------------------------------------------------------------------------------------------
main:
        // ---- prologue --------------------------------------------------------------------------
        stp     x29, x30, [sp, #-16]!   // push {frame pointer, link register}; pre-decrement sp.
                                        // THIS is the instruction that puts a return address into
                                        // writable memory next to local variables, which is the
                                        // structural reason stack buffer overflows became THE
                                        // vulnerability class. See chapter 03 section 3.8.3.
        mov     x29, sp                 // establish the new frame pointer

        // ---- body: bounded_sum(10, 1000) -------------------------------------------------------
        mov     w0, #10                 // first argument  -> w0    (n = 10)
        mov     w1, #1000               // second argument -> w1    (limit = 1000)
        bl      bounded_sum             // branch-with-link: jump, and put the address of the
                                        // NEXT instruction into lr so the callee can return
        // on return, w0 holds the result

        mov     w1, w0                  // printf's second argument
        adrp    x0, fmt                 // address of the format string, page-relative...
        add     x0, x0, :lo12:fmt       // ...plus its offset within that page.
                                        // Two instructions, because an AArch64 instruction is
                                        // 32 bits and cannot hold a 64-bit address.
        bl      printf

        // ---- epilogue --------------------------------------------------------------------------
        mov     w0, #0                  // return 0
        ldp     x29, x30, [sp], #16     // pop {fp, lr}; post-increment sp
        ret                             // branch to the restored lr


// -------------------------------------------------------------------------------------------------
// Read-only data. On a real system this lands in .rodata, which is mapped read-only — which is
// why you cannot overwrite a string literal, and why `char *s = "abc"; s[0] = 'x';` crashes in C.
// -------------------------------------------------------------------------------------------------
        .section .rodata
fmt:    .asciz  "%d\n"                  // .asciz appends the terminating NUL byte


// =================================================================================================
// THINGS TO TAKE AWAY
//
// 1. THERE IS NO `if` AND NO `for`. There is `cmp` (which sets flags) and a conditional branch
//    (which reads them). Every conditional in every language becomes that pair.
//
// 2. EVERY LOOP HAS THE SAME SHAPE:
//        a label
//        a compare
//        a FORWARD conditional branch  (the exit)
//        the body
//        a BACKWARD unconditional branch (the repeat)
//    Once you can spot that shape you can find loops in any disassembly, in any architecture,
//    in seconds. It is the highest-value pattern in the whole of native reversing.
//
// 3. ARGUMENTS ARRIVE IN REGISTERS, IN ORDER. w0, w1, w2... For `Java_com_app_Native_check(JNIEnv*,
//    jobject, jstring)`, x0 is the JNIEnv*, x1 is the jobject, and x2 is your actual first
//    argument. Getting this right is most of reading a JNI function. See 16-JNI.
//
// 4. `stp x29, x30, [sp, #-16]!` PUTS THE RETURN ADDRESS ON THE STACK. Local buffers live in the
//    same frame. Overflow one far enough and you overwrite the address the function will return
//    to. Every stack-smashing exploit is a consequence of this one line of prologue.
//
// 5. THE ADD IS 32-BIT. `add w2, w2, w3` operates on the low halves and wraps at 2^31 - 1 with no
//    exception, no flag anyone checks, and no log line. `add x2, x2, x3` would be 64-bit. When
//    you are hunting integer overflow in a .so, the w-versus-x distinction is the whole game.
//
// EXERCISES
//
// a. Compile sum_demo.c at -O0 and at -O2 and diff the assembly. At -O2 the compiler may replace
//    the entire loop with n*(n+1)/2. Explain what that means for anyone trying to reverse the
//    original algorithm.
//
// b. Find the same three-instruction loop shape in a real Android .so:
//        objdump -d libtarget.so | grep -B4 -A1 '\bb\.\(le\|lt\|ge\|gt\)\b' | head -40
//
// c. Write out, by hand, what the stack looks like immediately after main's prologue. Label the
//    saved lr. Then mark where a `char buf[64]` would sit, and draw the arrow that an overflow
//    would travel along.
// =================================================================================================
