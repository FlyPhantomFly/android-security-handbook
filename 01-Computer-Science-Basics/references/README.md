# 01 — Computer Science Basics · References

Every entry has a one-line annotation saying what it is good for and when to reach for it. Nothing
here is filler; if a link is listed, it earns its place for this chapter specifically.

Where a deep link would be guessed rather than known, the project or documentation root is linked and
the page is described instead. AOSP entries give **directory and file paths only** — never line
numbers, because they change with every release.

Back to [README.md](../README.md) · [cheatsheet.md](../cheatsheet.md) · [faq.md](../faq.md)

---

## Foundational books

| Book | Why it matters here |
|---|---|
| **Computer Systems: A Programmer's Perspective** — Bryant & O'Hallaron — <https://csapp.cs.cmu.edu/> | The single best match for this chapter: bits, integers, machine code, the memory hierarchy, linking, exceptions, virtual memory, and system-level I/O, all from a programmer's point of view. |
| **Operating Systems: Three Easy Pieces** — Remzi and Andrea Arpaci-Dusseau — <https://pages.cs.wisc.edu/~remzi/OSTEP/> | Free and complete online. Read the Virtualization part for processes, address spaces, and paging, and the Concurrency part for threads, locks, and condition variables. |
| **Modern Operating Systems** — Andrew S. Tanenbaum and Herbert Bos (Pearson) | Broader and more encyclopaedic than OSTEP; the reference to reach for when you want scheduling, deadlock, or filesystem design covered exhaustively. |
| **Computer Organization and Design** — Patterson & Hennessy (Morgan Kaufmann) — ARM Edition available | The hardware half of this chapter: instruction encoding, datapath, pipelining, and the memory hierarchy, taught against ARM rather than a toy machine. |
| **The Art of Debugging with GDB, DDD, and Eclipse** — Norman Matloff and Peter Jay Salzman (No Starch Press) | Teaches debugger technique as a discipline rather than a command list; the mental model transfers directly to LLDB and to on-device debugging. |
| **The Linux Programming Interface** — Michael Kerrisk (No Starch Press) | The definitive reference for the syscall surface this chapter introduces: processes, signals, memory mappings, file descriptors, and threads. |
| **Computer Architecture: A Quantitative Approach** — Hennessy & Patterson | Optional depth. Read it only if caches, speculation, and microarchitectural side channels become relevant to your work. |

---

## Free online courses and lecture series

| Resource | What you get |
|---|---|
| **OSTEP** — <https://pages.cs.wisc.edu/~remzi/OSTEP/> | The full book as free PDFs plus homework simulators; the paging and scheduling simulators are worth more than the reading alone. |
| **nand2tetris** — <https://www.nand2tetris.org/> | Build a computer from NAND gates up through an assembler, VM, and compiler; the fastest cure for "machine code is magic". |
| **MIT 6.828 / 6.1810 Operating System Engineering** — <https://pdos.csail.mit.edu/6.828/> | Labs that have you implement pieces of a real Unix-like kernel (xv6): system calls, page tables, traps, and threads. |
| **xv6 book** — linked from the 6.828 course page above | A short, readable operating system with commented source; the best way to see a page table and a trap handler as actual code. |
| **What Every Programmer Should Know About Memory** — Ulrich Drepper — <https://www.akkadia.org/drepper/cpumemory.pdf> | Long-form paper on caches, TLBs, NUMA, and why memory access patterns dominate performance. |
| **How To Write Shared Libraries** — Ulrich Drepper — <https://www.akkadia.org/drepper/dsohowto.pdf> | The clearest explanation of PLT, GOT, symbol visibility, and lazy binding you will find outside the linker source. |
| **Linux Inside** — <https://github.com/0xAX/linux-insides> | Community book walking through the Linux kernel's boot, memory management, and syscall paths with real source excerpts. |

---

## ARM architecture documentation

| Resource | What it covers |
|---|---|
| **Arm Architecture Reference Manual for A-profile architecture** (DDI 0487) — <https://developer.arm.com/documentation/ddi0487/latest/> | The authoritative specification: instruction encodings, exception levels EL0–EL3, system registers, and the memory model. Enormous — use it as a lookup, never as reading material. |
| **Arm developer documentation portal** — <https://developer.arm.com/documentation> | Searchable index of every Arm specification, including the AArch64 instruction set reference and the programmer's guides. |
| **ABI for the Arm 64-bit Architecture (AAPCS64) and related ABI documents** — <https://github.com/ARM-software/abi-aa> | The procedure call standard: argument registers, return values, callee-saved registers, stack alignment, and the ELF ABI for AArch64. The `aapcs64` document is the one you want for reading disassembly. |
| **Arm Cortex-A Series Programmer's Guide for ARMv8-A** — available from the documentation portal above | A gentler on-ramp than the ARM ARM: exception handling, the MMU, caches, and barriers explained with worked examples. |
| **Arm Memory Tagging Extension (MTE) documentation** — search the Arm documentation portal for "Memory Tagging Extension" | Explains the hardware behind Android's use-after-free and buffer-overflow detection; relevant once you reach [19-Memory](../../19-Memory/README.md). |

---

## Linux kernel documentation

| Resource | What it covers |
|---|---|
| **The Linux Kernel documentation** — <https://www.kernel.org/doc/html/latest/> | Entry point to every in-tree document, including the memory management, scheduler, and core API sections. |
| **The `/proc` filesystem** — <https://www.kernel.org/doc/html/latest/filesystems/proc.html> | Field-by-field description of `/proc/<pid>/maps`, `smaps`, `status`, and `stat`; the reference for decoding a memory map line. |
| **Memory management documentation** — <https://www.kernel.org/doc/html/latest/admin-guide/mm/index.html> | Transparent huge pages, overcommit behaviour, and the knobs that change how mappings behave. |
| **`proc(5)` man page** — <https://man7.org/linux/man-pages/man5/proc.5.html> | The other half of the `/proc` reference, often more readable than the kernel document. |
| **`mmap(2)`** — <https://man7.org/linux/man-pages/man2/mmap.2.html> | Every flag and protection constant, plus the exact failure modes and `errno` values. |
| **`mprotect(2)`** — <https://man7.org/linux/man-pages/man2/mprotect.2.html> | Page permission changes — the call every instrumentation framework and packer relies on. |
| **`fork(2)`** — <https://man7.org/linux/man-pages/man2/fork.2.html> | What exactly is and is not inherited by a child; the basis for understanding Zygote. |
| **`clone(2)`** — <https://man7.org/linux/man-pages/man2/clone.2.html> | The flags that turn one syscall into either a process or a thread. |
| **`execve(2)`** — <https://man7.org/linux/man-pages/man2/execve.2.html> | How a program image is replaced, including what happens to file descriptors, signals, and privileges. |
| **`ptrace(2)`** — <https://man7.org/linux/man-pages/man2/ptrace.2.html> | The request types behind debuggers, Frida attachment, and most anti-debug checks. |
| **`futex(2)`** — <https://man7.org/linux/man-pages/man2/futex.2.html> | The kernel side of userspace locking; explains why `strace` on a threaded app is full of `futex` calls. |
| **`signal(7)`** — <https://man7.org/linux/man-pages/man7/signal.7.html> | Complete signal table, default actions, and the async-signal-safety rules. |
| **`sigaction(2)`** — <https://man7.org/linux/man-pages/man2/sigaction.2.html> | Installing handlers and reading `siginfo_t`, including the `si_code` values that distinguish `SEGV_MAPERR` from `SEGV_ACCERR`. |
| **`elf(5)`** — <https://man7.org/linux/man-pages/man5/elf.5.html> | Every ELF header, section header, and program header field as a C structure with commentary. |
| **`syscalls(2)`** — <https://man7.org/linux/man-pages/man2/syscalls.2.html> | Index of the whole Linux system call surface with the kernel version each call appeared in. |
| **`ld.so(8)`** — <https://man7.org/linux/man-pages/man8/ld.so.8.html> | Dynamic linker behaviour, search paths, and the environment variables that change them. |
| **`pthreads(7)`** — <https://man7.org/linux/man-pages/man7/pthreads.7.html> | Thread semantics, what is per-thread versus per-process, and the attribute set including stack size. |
| **Kernel syscall table for arm64** — kernel source `include/uapi/asm-generic/unistd.h` | Canonical arm64 syscall numbers; arm64 uses the generic table rather than a private one. Browse it in any kernel source mirror. |

---

## ELF and ABI specifications

| Resource | What it covers |
|---|---|
| **System V ABI — generic (gABI)** — <https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html> | The base ELF specification: file header, sections, segments, symbol tables, relocations, and the dynamic section. |
| **Linux Foundation reference specifications archive** — <https://refspecs.linuxfoundation.org/> | Hosts the original ELF specification PDF, the processor supplements, and the Linux Standard Base documents. |
| **ELF for the Arm 64-bit Architecture** — in <https://github.com/ARM-software/abi-aa> | The AArch64 processor supplement: relocation types, program property notes, and platform-specific section semantics. |
| **x86-64 psABI** — <https://gitlab.com/x86-psABIs/x86-64-ABI> | The x86-64 processor supplement, useful when you compare calling conventions or work on an emulator image. |
| **DWARF Debugging Standard** — <https://dwarfstd.org/> | The format of the debug information `-g` produces and of the unwind tables in `.eh_frame`. |

---

## Compiler and toolchain documentation

| Resource | What it covers |
|---|---|
| **GCC online documentation** — <https://gcc.gnu.org/onlinedocs/> | Option reference for the whole compilation pipeline, including `-E`, `-S`, `-c`, `-save-temps`, and every hardening flag. |
| **Clang documentation** — <https://clang.llvm.org/docs/> | The compiler Android actually uses; see the AddressSanitizer, HWAddressSanitizer, UndefinedBehaviorSanitizer, and ShadowCallStack pages in particular. |
| **LLVM documentation** — <https://llvm.org/docs/> | Background on the IR, the LLD linker, and the `llvm-*` binary utilities shipped in the NDK. |
| **GNU binutils documentation** — <https://sourceware.org/binutils/docs/> | Manuals for `readelf`, `objdump`, `nm`, `as`, `ld`, `strings`, and `size` — the tools in the cheat sheet. |
| **GNU Make manual** — <https://www.gnu.org/software/make/manual/> | Enough build-system literacy to follow how an object file becomes a shared library. |

---

## Android-specific connections

AOSP is browsable at <https://cs.android.com/> (Android Code Search) and
<https://android.googlesource.com/> (Gitiles). Paths below are directories and files; open them in
either viewer.

| AOSP path | Why it matters for this chapter |
|---|---|
| `bionic/` — <https://android.googlesource.com/platform/bionic/> | Android's C library and dynamic linker; the concrete implementation of nearly every concept in this chapter. |
| `bionic/libc/SYSCALLS.TXT` | The table from which bionic's syscall wrappers are generated — the authoritative mapping of libc function to syscall on Android. |
| `bionic/libc/kernel/uapi/` | Sanitised kernel UAPI headers, including the `errno`, signal, `mmap`, and ELF constant definitions used by the NDK. |
| `bionic/libc/bionic/` | Implementations of `malloc` glue, `pthread_create`, `fork`, `errno`, and the thread-local storage setup. |
| `bionic/linker/` | The dynamic linker (`linker64`): ELF parsing, segment mapping, relocation processing, and `dlopen`. |
| `bionic/docs/` | Bionic's own design notes, including documents on the status of libc features and the ELF TLS implementation. |
| `art/` — <https://android.googlesource.com/platform/art/> | The Android Runtime: interpreter, JIT, AOT compiler, and garbage collector. |
| `art/runtime/` | The runtime core, including the interpreter and the managed-to-native transition code. |
| `art/runtime/jit/` | The JIT compiler and its code cache — the concrete example of writable-then-executable memory on Android. |
| `art/dex2oat/` | The ahead-of-time compiler that turns DEX into an OAT file at install or idle time. |
| `system/core/` — <https://android.googlesource.com/platform/system/core/> | `init`, `libcutils`, `liblog`, and other low-level userspace components. |
| **Android NDK documentation** — <https://developer.android.com/ndk> | Toolchain usage, the `.so` build process, and the ABI-specific behaviour of native code. |
| **Android ABI management** — <https://developer.android.com/ndk/guides/abis> | The supported ABIs (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`), their data model, and their calling conventions. |
| **Android platform documentation** — <https://source.android.com/> | Platform-level documentation including the security model, verified boot, and the kernel Android ships. |
| **Android 16 KB page size guidance** — search the NDK documentation above for "16 KB page size" | Explains the segment alignment requirement for native libraries on devices with 16 KiB pages. |

---

## Tools

| Tool | Link | Use in this chapter |
|---|---|---|
| **strace** | <https://strace.io/> | Trace system calls and their arguments; the fastest way to see the kernel boundary in action. |
| **ltrace** | packaged as `ltrace`; see `man ltrace` on your distribution | Trace calls into shared libraries through the PLT, complementing `strace`. |
| **GDB** | <https://sourceware.org/gdb/> | Breakpoints, register inspection, stack walking, and memory examination on host binaries. |
| **LLDB** | <https://lldb.llvm.org/> | The debugger shipped with the NDK; the one you will use for on-device native debugging. |
| **Ghidra** | <https://ghidra-sre.org/> · source at <https://github.com/NationalSecurityAgency/ghidra> | Free disassembler and decompiler with solid AArch64 support; see [57-Ghidra](../../57-Ghidra/README.md). |
| **radare2** | <https://rada.re/n/> · source at <https://github.com/radareorg/radare2> | Scriptable reverse engineering framework, useful for batch analysis; see [59-radare2](../../59-radare2/README.md). |
| **Compiler Explorer** | <https://godbolt.org/> | Type C or C++ on the left, see AArch64 assembly on the right, live. The single best tool for learning how source maps to instructions. |
| **binutils** | <https://sourceware.org/binutils/> | `readelf`, `objdump`, `nm`, `strings`, `size` — the ELF inspection toolkit. |
| **Valgrind** | <https://valgrind.org/> | Memory error detection on host builds; conceptually the ancestor of ASan and useful for understanding what those tools detect. |
| **QEMU** | <https://www.qemu.org/> | Run AArch64 binaries on an x86 host when you want to experiment without a device. |

---

## Papers and classic reading on memory corruption

These are the primary sources for the bug classes this chapter introduces. Read them for the
mechanism, not for the exploit code, most of which no longer works against modern mitigations.

| Work | Why it is worth reading |
|---|---|
| **Smashing the Stack for Fun and Profit** — Aleph One, *Phrack* issue 49, article 14 — <http://phrack.org/issues/49/14.html> | The paper that defined the stack buffer overflow: frame layout, saved return address overwrite, and why the copy direction matters. Everything about stack corruption descends from it. |
| **Once Upon a free()** — anonymous, *Phrack* issue 57 — <http://phrack.org/issues/57/9.html> | The heap counterpart: allocator metadata, free-list manipulation, and why heap exploitation is about shaping rather than overflowing. |
| **w00w00 on Heap Overflows** — Matt Conover and the w00w00 Security Team, 1999 | The other foundational heap paper; widely mirrored, cite by title and author. Explains overflow into adjacent object data rather than into metadata. |
| **The Advanced Return-into-lib(c) Exploits** — Nergal, *Phrack* issue 58 | Introduces chaining library calls to defeat non-executable stacks; the direct ancestor of return-oriented programming. |
| **Basic Integer Overflows** — blexim, *Phrack* issue 60 | Signed and unsigned confusion, truncation, and sign extension turned into memory corruption; the two's complement section of this chapter made concrete. |
| **Exploiting Format String Vulnerabilities** — scut / team teso, 2001 | Why a byte's meaning depends entirely on the convention in force, taken to its logical conclusion. |
| **Google Project Zero blog** — <https://googleprojectzero.blogspot.com/> | Current-generation write-ups; several Android posts walk a memory corruption bug from crash to full compromise using exactly this chapter's vocabulary. |
| **Android platform security model** — search <https://source.android.com/> for the security overview | Places the process, UID, and kernel boundaries of this chapter into Android's stated threat model. |

---

## Where to go next

| Chapter | What it builds on from here |
|---|---|
| [02-Linux-Basics](../../02-Linux-Basics/README.md) | Processes, signals, file descriptors, and `/proc` become daily shell work. |
| [03-Programming-Fundamentals](../../03-Programming-Fundamentals/README.md) | Compilation, interpretation, and data structures at source level. |
| [15-Native-Code](../../15-Native-Code/README.md) | ELF sections, PLT/GOT, NX, PIE, RELRO, and stack canaries as a hardening checklist. |
| [18-ARM](../../18-ARM/README.md) | AArch64 registers, AAPCS64, and reading real disassembly. |
| [19-Memory](../../19-Memory/README.md) | Address space layout, allocators, and memory corruption primitives. |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | How the kernel boundaries here are turned into the Android sandbox. |
| [53-Frida](../../53-Frida/README.md) | `ptrace`, `mmap`, and `mprotect` assembled into an instrumentation framework. |
