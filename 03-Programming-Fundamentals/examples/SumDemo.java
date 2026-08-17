/*
 * SumDemo.java — the chapter's reference program, compiled to BYTECODE and run by a VM.
 *
 * PURPOSE
 *   Version 3 of 4. Compare against sum_demo.py, sum_demo.c and sum_demo.s.
 *   This is the version that matters most for Android, because this is what an app is.
 *
 * BUILD AND RUN
 *   host $ javac SumDemo.java && java SumDemo
 *   host $ java SumDemo 100 1000
 *
 * SEE WHAT IT BECOMES — do this, it is the point of the file
 *   host $ javap -c -p SumDemo          # JVM bytecode, instruction by instruction
 *   host $ javap -v SumDemo             # plus the constant pool and the full class structure
 *   host $ xxd SumDemo.class | head     # the raw bytes; it starts with CAFEBABE
 *
 * THEN TAKE IT TO ANDROID
 *   host $ d8 SumDemo.class --output .          # produces classes.dex
 *   host $ baksmali d classes.dex -o smali/     # Dalvik bytecode, human readable
 *   host $ cat smali/SumDemo.smali
 *   Compare the Smali against the javap output. The JVM is a STACK machine (iload/iadd/istore);
 *   Dalvik is a REGISTER machine (add-int/2addr v2, v3). The control flow is identical.
 *   That comparison is the bridge from this chapter to 12-DEX-Internals and 14-Dalvik.
 *
 * WHAT TO NOTICE
 *   * Types are declared, like C. Sizes are fixed, like C. `int` is 32 bits and WRAPS, like C.
 *   * But the names survive into the compiled artefact. `strings SumDemo.class | grep bounded`
 *     finds `boundedSum`, and no build flag removes it — the runtime needs it for reflection
 *     and linking. That is why Android apps decompile to near-source-quality Java.
 *   * There is a compilation step, unlike Python, but the output is portable, unlike C.
 *
 * Chapter 03 — Programming Fundamentals, sections 2.3, 3.18 and 9.1
 */

public class SumDemo {

    /**
     * Sum 1..n, returning -1 if the running total ever exceeds limit.
     *
     * Compare line for line with bounded_sum() in sum_demo.c. They are the same function.
     * The important shared property: `int` is 32 bits, signed, and OVERFLOWS SILENTLY. Java
     * did not fix this — the Java Language Specification requires the wraparound behaviour.
     */
    static int boundedSum(int n, int limit) {
        int total = 0;
        for (int i = 1; i <= n; i++) {
            total = total + i;              // wraps silently past 2_147_483_647
            if (total > limit) {
                return -1;
            }
        }
        return total;
    }

    /**
     * The checked version. Math.addExact throws ArithmeticException rather than wrapping.
     *
     * This is what Java gives you that C does not: not automatic safety, but a standard-library
     * function that makes the safe path one word longer than the unsafe one.
     */
    static int boundedSumChecked(int n, int limit) {
        int total = 0;
        for (int i = 1; i <= n; i++) {
            total = Math.addExact(total, i);   // throws instead of wrapping
            if (total > limit) {
                return -1;
            }
        }
        return total;
    }

    public static void main(String[] args) {
        int n     = (args.length > 0) ? Integer.parseInt(args[0]) : 10;
        int limit = (args.length > 1) ? Integer.parseInt(args[1]) : 1000;

        System.out.println(boundedSum(n, limit));

        if (args.length > 2) {              // any third argument switches on the comparison
            System.out.println("Integer.MAX_VALUE = " + Integer.MAX_VALUE);
            System.out.println("MAX_VALUE + 1     = " + (Integer.MAX_VALUE + 1));
            try {
                System.out.println("checked: " + boundedSumChecked(n, limit));
            } catch (ArithmeticException e) {
                System.out.println("checked: refused — " + e.getMessage());
            }
        }
    }
}

/* ------------------------------------------------------------------------------------------
 * THE BYTECODE, ANNOTATED
 *
 * `javap -c -p SumDemo` produces roughly this for boundedSum. Every instruction is annotated
 * with the Java it came from. Work through it once by hand; it is twenty minutes and it makes
 * every later Smali listing in this repository readable.
 *
 *    0: iconst_0        // push the constant 0            \  int total = 0;
 *    1: istore_2        // pop into local slot 2          /
 *    2: iconst_1        // push 1                         \  int i = 1;
 *    3: istore_3        // pop into local slot 3          /
 *
 *    4: iload_3         // push i                         \
 *    5: iload_0         // push n  (slot 0 = param 1)      >  i <= n ?
 *    6: if_icmpgt 27    // if i > n, jump out of the loop /
 *
 *    9: iload_2         // push total                     \
 *   10: iload_3         // push i                          |  total = total + i;
 *   11: iadd            // pop two, add, push result       |
 *   12: istore_2        // pop into total                 /
 *
 *   13: iload_2         // push total                     \
 *   14: iload_1         // push limit                      >  total > limit ?
 *   15: if_icmple 21    // if total <= limit, continue    /
 *   18: iconst_m1       // push -1                        \  return -1;
 *   19: ireturn         // return it                      /
 *
 *   21: iinc 3, 1       // i = i + 1, in place            }  the increment
 *   24: goto 4          // jump back to the test          }  the backward branch
 *
 *   27: iload_2         // push total                     \  return total;
 *   28: ireturn         // return it                      /
 *
 * THREE OBSERVATIONS THAT MATTER FAR BEYOND THIS FILE
 *
 * 1. THE LOOP DOES NOT EXIST. There is no `for` instruction. There is a comparison, a forward
 *    conditional branch (the exit at offset 6) and a backward unconditional branch (the repeat
 *    at offset 24). Every loop, in every language, at every level, is that shape.
 *
 * 2. THE JVM IS A STACK MACHINE. `iload` pushes, `iadd` pops two and pushes one, `istore` pops.
 *    Dalvik and ART are REGISTER machines, so the same method in Smali reads
 *    `add-int/2addr v2, v3` — no push, no pop. Control flow is identical. Read 14-Dalvik next.
 *
 * 3. THE NAMES SURVIVED. `boundedSum`, the parameter types and the return type are all in the
 *    class file, because the runtime needs them. No compiler flag removes them. Obfuscation
 *    (40-Obfuscation) exists precisely because of this, and it can only RENAME them, never
 *    delete them.
 *
 * EXPERIMENTS
 *
 * a. Run: java SumDemo 100000 2147483647
 *    Compare the answer with `python3 sum_demo.py 100000 2147483647`. Java wraps; Python does
 *    not. "Java is memory safe" and "Java prevents integer overflow" are different claims, and
 *    only the first is true.
 *
 * b. Run: java SumDemo 100000 2147483647 show
 *    Watch Math.addExact refuse instead of wrapping. That is the fix, and it is one word.
 *
 * c. Run: javap -v SumDemo | sed -n '/Constant pool/,/^{/p'
 *    Every string, name and type signature the class uses, in one table, exactly once. That is
 *    the same idea as a DEX string pool — see labs/lab-02.
 * ------------------------------------------------------------------------------------------ */
