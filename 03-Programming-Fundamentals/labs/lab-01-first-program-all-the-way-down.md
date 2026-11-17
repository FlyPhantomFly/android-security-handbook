# Lab 01 — Your first program, all the way down

**Difficulty:** Beginner — genuinely. If you have never written a line of code, start here.
**Time:** 2–3 hours
**Prerequisites:** [Chapter 01](../../01-Computer-Science-Basics/README.md),
[Chapter 03 §2, §3.1–§3.8](../README.md)

---

## Objective

Write one small program in four languages, then follow it downwards through every stage of
translation until you can **point at the exact bytes in a file that are your `if` statement**.

By the end you will have seen, with your own eyes, that source code, bytecode, assembly and machine
code are the same program in different clothes. That single realisation is what the rest of this
repository is built on. Everything about DEX files, ART, Smali and hooking becomes ordinary once you
have actually watched it happen once.

> **Mental Model.** You are not learning four languages. You are learning that there is one
> program, and four ways of writing it down — the way that suits a human, the way that suits a
> compiler, the way that suits a virtual machine, and the way that suits silicon.

---

## Setup

You need a terminal and three toolchains. Any Linux, macOS, or Windows with WSL or Git Bash.

```bash
# host — check what you have
python3 --version
gcc --version          # or: clang --version
javac -version         # from a JDK; `java -version` alone is not enough
```

If any are missing:

| Missing | Get it |
|---|---|
| `python3` | Preinstalled on Linux/macOS. Windows: https://python.org |
| `gcc` | Linux: `sudo apt install build-essential`. macOS: `xcode-select --install` |
| `javac` | `sudo apt install default-jdk`, or https://adoptium.net |
| `xxd`, `objdump`, `readelf` | Part of `binutils`; almost always already present |

You do **not** need an IDE. An IDE hides exactly the things this lab is about.

---

## Part 1 — Write it four times

The program: sum the integers from 1 to *n*, but stop and report failure if the running total ever
exceeds a limit.

Reference implementations are in [`../examples/`](../examples/). **Type them out rather than copying
them.** Typing forces you to read every character, and the typos you make and fix are where the
learning is.

### Step 1.1 — Python

```bash
# host
mkdir -p ~/lab01 && cd ~/lab01
```

Create `sum_demo.py`:

```python
def bounded_sum(n, limit):
    total = 0
    for i in range(1, n + 1):
        total = total + i
        if total > limit:
            return -1
    return total

print(bounded_sum(10, 1000))
```

```bash
# host
python3 sum_demo.py          # prints 55
```

**Q1.** Where is the program right now? Answer precisely: which file, and in what form?

**Q2.** Delete `sum_demo.py` and try to run it again. What happens? What does that tell you about
what "the program" *is* for an interpreted language?

(Recreate it before continuing.)

### Step 1.2 — C

Create `sum_demo.c`:

```c
#include <stdio.h>

int bounded_sum(int n, int limit) {
    int total = 0;
    for (int i = 1; i <= n; i++) {
        total = total + i;
        if (total > limit) {
            return -1;
        }
    }
    return total;
}

int main(void) {
    printf("%d\n", bounded_sum(10, 1000));
    return 0;
}
```

```bash
# host — -O0 disables optimisation so the output matches the source; -g keeps debug symbols
gcc -O0 -g sum_demo.c -o sum_demo
./sum_demo                   # prints 55
```

**Q3.** How large is `sum_demo.c`? How large is `sum_demo`? Why is the second so much bigger, when it
contains *less* information?

**Q4.** Now delete `sum_demo.c` and run `./sum_demo` again. It still works. Compare that with Q2 and
state the difference in one sentence.

(Recreate the source before continuing.)

### Step 1.3 — Java

Create `SumDemo.java`:

```java
public class SumDemo {
    static int boundedSum(int n, int limit) {
        int total = 0;
        for (int i = 1; i <= n; i++) {
            total = total + i;
            if (total > limit) {
                return -1;
            }
        }
        return total;
    }

    public static void main(String[] args) {
        System.out.println(boundedSum(10, 1000));
    }
}
```

```bash
# host
javac SumDemo.java
ls -l SumDemo.class
java SumDemo                 # prints 55
```

**Q5.** `javac` produced `SumDemo.class`. Try running it directly: `./SumDemo.class`. Why does that
fail, and what does `java SumDemo` do that makes it work?

### Step 1.4 — Read the assembly

You will not write this one. Read it, and then compare it with what the compiler really produced.

```bash
# host — what gcc actually emits
gcc -O0 -S sum_demo.c -o sum_demo.s
cat sum_demo.s
```

Compare it against the teaching version in [`../examples/sum_demo.s`](../examples/sum_demo.s), which
is simplified AArch64.

**Q6.** Find the loop in the real assembly output. There is no `for` instruction. What three things
did the compiler emit instead? (Look for a label, a compare, a conditional branch and an
unconditional branch.)

**Q7.** Find the `if (total > limit)`. Which two instructions is it?

---

## Part 2 — Watch the translation happen

This is the part that makes the abstraction ladder real.

### Step 2.1 — Java bytecode, instruction by instruction

```bash
# host
javap -c -p SumDemo
```

You will see something close to:

```
   0: iconst_0
   1: istore_2
   2: iconst_1
   3: istore_3
   4: iload_3
   5: iload_0
   6: if_icmpgt     27
   9: iload_2
  10: iload_3
  11: iadd
  12: istore_2
  ...
  21: iinc          3, 1
  24: goto          4
  27: iload_2
  28: ireturn
```

Work through it with the reference table:

| Instruction | Means |
|---|---|
| `iconst_0` | Push the integer constant 0 onto the operand stack |
| `istore_2` | Pop, and store into local variable slot 2 |
| `iload_3` | Push the value in local slot 3 |
| `iadd` | Pop two, add, push the result |
| `if_icmpgt X` | Pop two; if the first is greater, jump to offset X |
| `iinc 3, 1` | Add 1 to local slot 3, in place |
| `goto X` | Jump to offset X unconditionally |
| `ireturn` | Return the integer on top of the stack |

**Q8.** Which local slot holds `n`? Which holds `total`? Which holds `i`? (Hint: parameters get the
lowest slots, in order, for a `static` method.)

**Q9.** Annotate every one of the ~15 instructions with the line of Java it came from. Write it out.
This is tedious and it is the single most useful twenty minutes in the lab.

**Q10.** The JVM has no `for` instruction and no `if` instruction. Describe, in one sentence each,
what a loop and a conditional actually *are* at this level.

**Q11.** Notice that `boundedSum`, `int`, and the parameter types are all present in the output. What
does that mean for someone who receives only `SumDemo.class`?

### Step 2.2 — Machine code

```bash
# host
objdump -d sum_demo | sed -n '/<bounded_sum>:/,/ret/p'
```

Each line has three parts: an address, the raw bytes, and the disassembled instruction.

```
0000000000001129 <bounded_sum>:
    1129:  f3 0f 1e fa        endbr64
    112d:  55                 push   %rbp
    112e:  48 89 e5           mov    %rsp,%rbp
    ...
```

**Q12.** Pick any single instruction. Write down its address, its bytes, and what it does. Those
bytes exist in the file on disk — find them:

```bash
# host — the address above is a virtual address; find the file offset
readelf -S sum_demo | grep -A1 '\.text'
xxd -s <file_offset> -l 64 sum_demo
```

**Q13.** You have now located, in a file, the specific bytes that are your `if` statement. Write down
the offset. This is the moment the lab exists for — sit with it.

### Step 2.3 — Compare the artefacts

```bash
# host
ls -l sum_demo.py sum_demo.c sum_demo SumDemo.class
file sum_demo.py sum_demo SumDemo.class
strings sum_demo | head -30
strings SumDemo.class | head -30
```

Fill this in from your own observations:

| Artefact | Size | `file` says | Are the function names visible in `strings`? | Could you recover the source? |
|---|---|---|---|---|
| `sum_demo.py` | | | | |
| `sum_demo` (ELF) | | | | |
| `SumDemo.class` | | | | |

**Q14.** Which artefact leaks the most information about the original source? Which the least?

**Q15.** Based on that table alone, predict: will an Android app's Java code or its `.so` files be
easier to reverse engineer? Explain why in one sentence, using the words from your table.

---

## Part 3 — Break it deliberately

Understanding comes faster from breaking things than from reading them.

### Step 3.1 — Make it overflow

```bash
# host
python3 -c "print(2**31 - 1 + 1)"
```

Python prints `2147483648` — Python integers do not overflow.

Now in C:

```c
/* overflow_check.c */
#include <stdio.h>
int main(void) {
    int x = 2147483647;
    printf("%d\n", x + 1);
    return 0;
}
```

```bash
# host
gcc -O0 overflow_check.c -o overflow_check && ./overflow_check
```

**Q16.** What did C print? Why?

**Q17.** Do the same in Java. Does Java behave like Python or like C? What does that tell you about
"Java is a safe language"?

**Q18.** Now compile the C version with the sanitiser and run it again:

```bash
# host
gcc -fsanitize=undefined -O0 overflow_check.c -o overflow_check_san && ./overflow_check_san
```

What did it tell you, and how long did it take? Remember this — it is
[§9.2](../README.md#92-intermediate--a-planted-integer-overflow-found-four-ways)'s point.

### Step 3.2 — Make it recurse forever

```python
# host — deliberately broken
def f(n):
    return f(n + 1)
f(0)
```

**Q19.** What error do you get, and what does the number in it tell you about how many frames fit on
the stack?

**Q20.** Connect this to a real vulnerability: a parser that recurses once per level of nesting, fed
ten thousand nested arrays. What is the impact and what is the fix?

### Step 3.3 — Change one bit

```bash
# host — make a copy so you can compare
cp sum_demo sum_demo_patched
```

Find the byte encoding the comparison in `bounded_sum` (from Q12/Q13), change it with a hex editor
or `printf`, and run the patched binary.

```bash
# host — example: write byte 0x90 (x86 nop) at offset N
printf '\x90' | dd of=sum_demo_patched bs=1 seek=<N> conv=notrunc
./sum_demo_patched
```

**Q21.** Did it still run? Did it produce a different answer, crash, or behave identically?

**Q22.** You have just patched a binary. Write one sentence explaining what "patching a check" means
in a security context, now that you have done it.

---

## Success criteria

- [ ] All four versions written by hand and run, all printing 55
- [ ] You can explain why deleting the `.py` breaks it and deleting the `.c` does not
- [ ] Every JVM bytecode instruction annotated with its source line
- [ ] You identified which local slot holds `n`, `total` and `i`
- [ ] You located the loop in real compiler-generated assembly and named its three components
- [ ] **You found the actual bytes of your `if` statement in the ELF file and recorded the offset**
- [ ] The artefact comparison table is filled in from your own observations
- [ ] You observed integer overflow in C, in Java, and its absence in Python
- [ ] You ran a sanitiser and saw it name the exact line
- [ ] You crashed a program with infinite recursion and explained the security relevance
- [ ] You patched one byte in a compiled binary and observed the result

---

## Debrief

Answer in writing. These are the point of the lab.

1. In one paragraph, and without using the word "somehow", explain what happens between typing
   `javac SumDemo.java` and seeing `55` on screen.
2. The four versions of the program look nothing alike. In what sense are they the same program, and
   in what sense are they genuinely different?
3. `SumDemo.class` still contains the name `boundedSum`. `sum_demo` does not contain `bounded_sum`
   in any useful way. Why is that difference *designed in* rather than accidental?
4. You found the bytes of your `if` statement. If you could change any byte in that file, what would
   you be able to make the program do? What could you *not* make it do?
5. A colleague says "Java is memory safe, so we do not need to worry about integer overflow". Using
   your Q17 result, correct them precisely — including what Java *does* protect you from.
6. Which of the four representations would you rather be handed on an engagement, and why? Which
   would a developer trying to hide something rather give you?

---

## Where this goes next

You now know what a program is at four levels. [Lab 02](lab-02-hashmap-and-dex-strings.md) takes one
data structure and follows it from your own implementation into a real Android APK, which is the same
move applied to data rather than code.

If any part of this lab felt fast, the fix is repetition rather than reading: do it again with a
different program — one that takes an argument, or one with two functions — and watch how the extra
function appears in the bytecode and in the assembly.
