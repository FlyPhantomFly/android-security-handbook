# 03 — Programming Fundamentals — Annotated References

Every entry has a one-line note saying why you would open it. Free unless marked otherwise.

If you read **one** thing from this page, read *Operating Systems: Three Easy Pieces*. If you read
**two**, add *Crafting Interpreters*. Between them they explain most of why Android works the way it
does.

---

## Start here if this chapter was your first exposure to code

| Resource | Why |
|---|---|
| [Automate the Boring Stuff with Python](https://automatetheboringstuff.com/) | Free. The gentlest genuine start, and it produces useful scripts from chapter one rather than toy exercises |
| [Python official tutorial](https://docs.python.org/3/tutorial/) | Unusually well written for an official document; read it after Sweigart, not before |
| [Exercism](https://exercism.org/) | Free, mentored practice in 50+ languages. The mentoring is the part that makes it work |
| [The Missing Semester of Your CS Education](https://missing.csail.mit.edu/) | MIT. Shell, editors, git, debugging, profiling — everything courses assume you already know |
| [Learn X in Y Minutes](https://learnxinyminutes.com/) | A whole language's syntax on one page. Use it to *read* an unfamiliar language, which is most of this job |
| [Godbolt Compiler Explorer](https://godbolt.org/) | Paste code, watch the assembly appear as you type. The single best intuition-builder for [§2.3](../README.md#23-the-same-program-four-ways) |

---

## Systems: memory, the stack, the heap, the machine

| Resource | Why |
|---|---|
| [Operating Systems: Three Easy Pieces](https://pages.cs.wisc.edu/~remzi/OSTEP/) | Free. The best explanation anywhere of processes, virtual memory, the stack and the heap. Directly underpins [§3.1](../README.md#31-variables-and-memory--what-a-variable-actually-is) and [§3.14](../README.md#314-memory-management--manual-versus-garbage-collected) |
| [Computer Systems: A Programmer's Perspective](http://csapp.cs.cmu.edu/) | *Not free.* Bits, two's complement, assembly, linking. The machine-level view this chapter compresses |
| [Beej's Guide to C Programming](https://beej.us/guide/bgc/) | Free, readable, and honest about pointers instead of apologetic |
| [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/) | Free. Sockets from first principles; background for every networking chapter here |
| [What Every Programmer Should Know About Memory](https://people.freebsd.org/~lstewart/articles/cpumemory.pdf) | Drepper. Dense and free. Why data layout and cache behaviour matter — the reason arrays beat linked lists in practice |
| [What Every Computer Scientist Should Know About Floating-Point Arithmetic](https://docs.oracle.com/cd/E19957-01/806-3568/ncg_goldberg.html) | Goldberg. The authoritative answer to the `0.1 + 0.2` question |
| [The Linux Programming Interface](https://man7.org/tlpi/) | *Not free.* The reference for syscalls, processes and signals when you need certainty |

---

## How languages are actually implemented

| Resource | Why |
|---|---|
| [Crafting Interpreters](https://craftinginterpreters.com/) | Free online. Builds an interpreter, then a **bytecode virtual machine**, from scratch. The fastest route to genuinely understanding [§3.18](../README.md#318-compilation-interpretation-bytecode-vms-jit-and-aot) and therefore ART |
| [Writing an Interpreter in Go](https://interpreterbook.com/) | *Not free.* The most approachable compiler book available; the Go is incidental |
| [Compilers: Principles, Techniques and Tools](https://www.pearson.com/) ("the Dragon Book") | *Not free.* The classic reference. Consult it; do not read it cover to cover |
| [A Tour of the JVM](https://docs.oracle.com/javase/specs/jvms/se17/html/) | The bytecode instruction set behind `javap -c` output |
| [Dalvik bytecode reference](https://source.android.com/docs/core/runtime/dalvik-bytecode) | The instruction set you will read in Smali — register-based, unlike the JVM's stack machine |

---

## Algorithms and data structures

| Resource | Why |
|---|---|
| [Open Data Structures](https://opendatastructures.org/) | Free, rigorous, covers exactly [§3.9](../README.md#39-data-structures-i--arrays-linked-lists-stacks-queues) to [§3.11](../README.md#311-data-structures-iii--trees-and-graphs) |
| [Big-O Cheat Sheet](https://www.bigocheatsheet.com/) | One page, every common structure and algorithm. Pin it |
| [VisuAlgo](https://visualgo.net/) | Animated hash tables, trees and sorting. Watch a hash table degrade under collisions rather than reading about it |
| [Hash collision DoS (28c3)](https://media.ccc.de/) | The talk that made hash-flooding a mainstream concern; background for [§3.10.6](../README.md#3106-hash-collision-as-a-denial-of-service-attack) |

---

## Official language and platform documentation

| Resource | Why |
|---|---|
| [The Java Language Specification](https://docs.oracle.com/javase/specs/) | Normative on integer overflow, string interning, and every "does it really do that?" question |
| [The Java Virtual Machine Specification](https://docs.oracle.com/javase/specs/jvms/se17/html/) | The bytecode reference |
| [Kotlin documentation](https://kotlinlang.org/docs/home.html) | Especially null safety, which is the strongest argument for Kotlin over Java |
| [cppreference (C)](https://en.cppreference.com/w/c) | The C reference that is actually accurate |
| [cppreference (C++)](https://en.cppreference.com/w/cpp) | Same, for the language most of AOSP's native side is written in |
| [Python documentation](https://docs.python.org/3/) | |
| [DEX format](https://source.android.com/docs/core/runtime/dex-format) | Where [§3.10](../README.md#310-data-structures-ii--hash-maps-and-why-they-matter-for-dex) pays off |
| [Android NDK guides](https://developer.android.com/ndk/guides) | Where Java's memory safety ends |
| [ARM Architecture Reference Manual (AArch64)](https://developer.arm.com/documentation/ddi0487/latest/) | The authority for every instruction in a `.so`. Search it; do not read it |
| [System V ABI / AAPCS64](https://github.com/ARM-software/abi-aa) | The calling convention: which register holds which argument. Needed constantly when reversing native code |

---

## Secure coding and vulnerability classes

| Resource | Why |
|---|---|
| [CWE — Common Weakness Enumeration](https://cwe.mitre.org/) | The standard taxonomy. This chapter creates CWE-190 (integer overflow), CWE-787 (OOB write), CWE-125 (OOB read), CWE-416 (use after free), CWE-476 (null deref) |
| [SEI CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c) | Rule by rule, with compliant and non-compliant examples. INT30-C and INT32-C are [§3.4](../README.md#34-integer-overflow-as-a-vulnerability-class) |
| [Google Security Blog — memory safety](https://security.googleblog.com/) | The data behind "~70% of critical vulnerabilities are memory safety", and the reasoning behind Rust in AOSP |
| [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) | Turn this on and it finds the bug in [§9.2](../README.md#92-intermediate--a-planted-integer-overflow-found-four-ways) in one second |
| [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) | Catches signed integer overflow at the exact line and column |
| [libFuzzer tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md) | The highest yield per engineering hour of anything in this list |
| [OWASP MASVS](https://mas.owasp.org/MASVS/) | Where these fundamentals map onto mobile requirements |
| [Smashing The Stack For Fun And Profit](http://phrack.org/issues/49/14.html) | Aleph One, 1996. Historically the paper that made [§3.8.3](../README.md#383-the-call-stack-drawn) matter. Read it for the mental model, not for a working exploit |

---

## Version control

| Resource | Why |
|---|---|
| [Pro Git](https://git-scm.com/book/en/v2) | Free. Chapter 10, "Git Internals", is the one that makes the DAG model in [§3.19.2](../README.md#3192-the-mental-model-a-dag-of-snapshots) click |
| [Learn Git Branching](https://learngitbranching.js.org/) | Interactive DAG visualiser. Twenty minutes here beats a week of memorising commands |
| [git-filter-repo](https://github.com/newren/git-filter-repo) | The correct way to purge a secret from history — and a good demonstration of how much easier it is not to commit it |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Scans history for secrets. Run it on any repository you are given source access to |

---

## Debugging

| Resource | Why |
|---|---|
| [GDB documentation](https://sourceware.org/gdb/current/onlinedocs/gdb/) | Especially **watchpoints**, which answer "what is corrupting this?" — a question printing cannot |
| [LLDB tutorial](https://lldb.llvm.org/use/tutorial.html) | The debugger for Android native code |
| [Debugging: The 9 Indispensable Rules](https://debuggingrules.com/) | *Not free, short.* The best thing written on debugging as a discipline. "Quit thinking and look" is worth the price alone |
| [Android Studio debugger guide](https://developer.android.com/studio/debug) | Breakpoints, conditional breakpoints and evaluate-expression on a live app |
| [rr (record and replay)](https://rr-project.org/) | Deterministic replay debugging on Linux; step *backwards* through an execution |

---

## Practice

| Resource | Why |
|---|---|
| [Exercism](https://exercism.org/) | Language fluency with human feedback |
| [Advent of Code](https://adventofcode.com/) | Small, self-contained problems. Good for building the "I can just write a script for that" reflex |
| [pwn.college](https://pwn.college/) | Free. Turns [§3.8](../README.md#38-functions-the-call-stack-and-recursion) and [§3.13](../README.md#313-pointers-and-references) into hands-on exploitation |
| [Nightmare (binary exploitation course)](https://guyinatuxedo.github.io/) | Free, worked examples from trivial to hard |
| [Microcorruption](https://microcorruption.com/) | Free. Assembly and memory corruption in a browser, no setup at all. The best on-ramp to reading disassembly |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [01-Computer-Science-Basics](../../01-Computer-Science-Basics/README.md) | The machine this chapter writes programs for |
| [02-Linux-Basics](../../02-Linux-Basics/README.md) | Processes, memory and the kernel |
| [04-Java](../../04-Java/README.md) | The next chapter — every concept here, in Java specifics |
| [05-Kotlin](../../05-Kotlin/README.md) | Null safety and what modern Android is written in |
| [18-ARM](../../18-ARM/README.md) | The bottom of the abstraction ladder from §2.1 |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | Where §3.18's theory becomes a real runtime |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The string pool that §3.10 prepares you for |
| [13-ART](../../13-ART/README.md) | Interpretation, JIT and AOT in practice |
| [14-Dalvik](../../14-Dalvik/README.md) | The Smali you will read, instruction by instruction |
| [16-JNI](../../16-JNI/README.md) | Where Java's memory safety ends |
| [19-Memory](../../19-Memory/README.md) | Heap dumps, and finding the secrets §3.14.4 warns about |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What survives renaming, and why |
| [53-Frida](../../53-Frida/README.md) | The instrumentation used in §7 |
| [65-Hooking](../../65-Hooking/README.md) | Function calls, from first principles, weaponised |
