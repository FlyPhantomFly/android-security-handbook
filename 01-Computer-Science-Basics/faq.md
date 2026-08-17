# 01 — Computer Science Basics · FAQ

The questions people actually ask when they start this chapter, including the ones they are
embarrassed to ask out loud. Nothing here is too basic to be worth answering properly.

Companion to [README.md](README.md) · [cheatsheet.md](cheatsheet.md) · [mindmap.md](mindmap.md)

---

## Motivation

### Why do I need to learn any of this to test Android apps?

Because the moment a tool stops working, the tool cannot help you. You will type
`frida -U -f com.target -l bypass.js`, and one day it will print an error about failing to attach, or
the app will die silently the instant Frida connects, or your hook will fire but the return value you
force will be ignored. At that point the only way forward is to know what Frida was actually doing:
it attached to the process with the `ptrace` system call, allocated a fresh memory region with
`mmap`, wrote a trampoline into it, flipped the page permissions with `mprotect`, and redirected a
function's first instructions to that trampoline. Every noun in that sentence is a chapter 01 concept.
If those words are opaque, you are reduced to searching for a different script and hoping.

The same applies to findings, not just tools. A report that says "the app crashed when I sent a long
string" is worth very little. A report that says "the app crashed with `SIGSEGV` at `SEGV_ACCERR`
inside `libfoo.so` after a 512-byte input overwrote the saved link register in the stack frame, and
the crash address was attacker-controlled" is worth a bounty, because it demonstrates control. The
difference between those two sentences is this chapter.

> **🧠 Mental Model** — Tools are opinions about the machine. When two tools disagree, or when one
> fails, only knowledge of the machine breaks the tie.

There is also a career-shaped reason. Almost everyone who calls themselves a mobile pentester can run
MobSF and JADX. The people who get paid well are the ones who can read a disassembled function, spot
that a length check uses a signed comparison, and explain why that is exploitable. That skill sits on
top of exactly the material in this chapter, and there is no shortcut around it.

### How much of this do I need before chapter 02?

Less than you fear, but the parts you do need must be solid rather than vague. Before you open
[02-Linux-Basics](../02-Linux-Basics/README.md), you should be able to answer these without looking
anything up: what a bit and a byte are, why hexadecimal is used, what a process is and how it differs
from a program, what a thread is, roughly what the stack and the heap each hold, what "virtual
memory" means at the level of "each process sees its own private address space", and what a system
call is. That is about a third of the chapter.

The rest — the details of AAPCS64 register roles, ELF section layout, allocator internals, page table
levels, futexes — can be read once for orientation and then treated as a reference you return to.
You will genuinely need AArch64 registers and calling conventions by [18-ARM](../18-ARM/README.md),
ELF details by [15-Native-Code](../15-Native-Code/README.md), and allocator internals by
[19-Memory](../19-Memory/README.md). Reading them now means the later chapters feel like revision
instead of ambush.

Here is a concrete self-test. If you can look at the line
`7f8a1c0000-7f8a1e0000 r-xp 00000000 fd:00 1234 /system/lib64/libc.so` from a process memory map and
explain every field, you are ready to move on. If you cannot, reread the virtual memory and ELF
sections rather than pushing forward.

---

## Bits, bytes, and numbers

### What actually is a bit?

A bit is one distinguishable physical state, interpreted as one of two symbols that we conventionally
write as `0` and `1`. Inside a CPU it is usually a voltage level held by a transistor arrangement:
below a threshold means `0`, above it means `1`. Inside flash storage it is an amount of charge
trapped on a floating gate. Over a radio link it is a modulation state. The physics changes; the
abstraction does not, and that is the entire point of the abstraction.

A bit on its own carries almost no information, so hardware groups bits into bytes of eight. Eight
bits gives 2^8 = 256 distinct patterns, which was historically enough for one text character plus
control codes, and it remains the smallest unit that memory hardware will let you address
individually. When you read that a variable is "at address `0x7f8a1c0000`", the address identifies one
byte, not one bit. There is no such thing as a pointer to a bit in C.

Everything else is layered convention on top. The same byte `0x41` is the number 65 if you agree to
read it as an unsigned integer, the letter `A` if you agree to read it as ASCII, part of an ARM
instruction if the CPU fetches it as code, and a red channel value if a graphics driver hands it to a
display. Bytes have no intrinsic type. Confusion about which convention is in force at a given moment
is the root of a large fraction of security bugs, including type confusion and format-string bugs.

> **📖 Definition** — **Bit**: a single binary digit, the smallest unit of information.
> **Byte**: eight bits, the smallest individually addressable unit of memory.
> **Nibble**: four bits, exactly one hexadecimal digit.

### Why hexadecimal instead of decimal?

Because hexadecimal lines up with binary and decimal does not. One hex digit is exactly four bits, so
one byte is exactly two hex digits and a 64-bit address is exactly sixteen. If you see the byte
`0xC3`, you can convert it to `1100 0011` in your head by expanding each digit independently: `C` is
`1100`, `3` is `0011`. Try the same with the decimal value 195 and you have to do arithmetic. When you
are staring at a permission bitmask or a flags field, hex lets you read individual bits off the page.

The second reason is that hardware boundaries are powers of two, and powers of two are round numbers
in hex but ugly in decimal. A page is `0x1000` bytes, which is obviously "a 1 followed by twelve zero
bits", so page-aligning an address means zeroing the last three hex digits. In decimal that same page
is 4096 bytes, and page-aligning becomes a division. Compare these two views of the same facts:

| Quantity | Decimal | Hexadecimal | What hex makes obvious |
|---|---|---|---|
| Page size | 4096 | `0x1000` | Offset is the low 3 hex digits |
| Page mask | 4294963200 | `0xFFFFF000` | It is "clear the offset" |
| Max unsigned byte | 255 | `0xFF` | All eight bits set |
| Max signed 32-bit | 2147483647 | `0x7FFFFFFF` | Sign bit clear, everything else set |
| Min signed 32-bit | −2147483648 | `0x80000000` | Only the sign bit set |

The third reason is purely social: every tool you will use — `xxd`, `readelf`, `objdump`, `gdb`,
Ghidra, Frida — prints addresses and byte values in hex. Fighting that convention costs you time on
every single command you run.

### What is endianness and when will it actually bite me?

Endianness is the order in which the bytes of a multi-byte value are laid out in memory. Take the
32-bit value `0x12345678`. On a little-endian machine the least significant byte comes first, so
memory holds `78 56 34 12`. On a big-endian machine the most significant byte comes first, so memory
holds `12 34 56 78`. Neither is more correct; they are two conventions that both exist for historical
reasons, and ARM hardware can technically do either, though Android always runs little-endian.

It bites you in three specific situations, and almost never anywhere else. The first is reading hex
dumps. When you dump a struct with `xxd` and see `78 56 34 12`, the value is `0x12345678`, and if you
read it left to right you will chase a number that does not exist. The second is parsing network
traffic or file formats by hand: IP, TCP, TLS, and Java `.class` files are big-endian, while DEX,
ELF-on-Android, and anything the device wrote natively are little-endian. Mixing the two produces
values that are absurd rather than subtly wrong, which is at least a fast failure. The third is
writing exploit payloads: an address you want the CPU to load must be packed in the target's byte
order, which is why Python exploit scripts are full of `struct.pack("<Q", addr)` with the `<` meaning
little-endian.

```bash
# runs on your host machine — see endianness directly
printf '\x78\x56\x34\x12' > /tmp/le.bin
xxd /tmp/le.bin            # shows: 7856 3412
od -A d -t x4 /tmp/le.bin  # shows: 12345678  (interpreted as a 32-bit int)
```

> **🔍 Pentester's Note** — When a value from a hex dump "looks reversed", it is not corrupt, it is
> little-endian. This is the single most common false alarm for people new to binary formats.

---

## Programs, processes, and threads

### What is the difference between a program and a process?

A program is a file. It is a passive sequence of bytes on storage — an ELF binary such as
`/system/bin/app_process64`, or a DEX file inside an APK — that describes what should happen if
someone runs it. Nothing about a program is running; it has no memory, no registers, no identity, and
copying it to another device changes nothing about it.

A process is a program that has been loaded and given the resources needed to execute: a private
virtual address space, a set of register values including a program counter, a process identifier
(PID), an owning user and group ID, an open file table, a signal disposition table, and an entry in
the kernel's task list. The kernel represents all of that in a structure called the process control
block (in Linux, `struct task_struct`). One program can back many processes at once — every Chrome
renderer is the same binary — and each process has its own separate copy of everything mutable.

On Android this distinction is unusually visible, because apps do not start by loading their own
binary. The Zygote process is already running with the framework classes and shared libraries loaded,
and starting an app forks Zygote and specialises the child: the child gets a new PID, a new UID
assigned per app, a new SELinux context, and then loads the app's DEX. The program on disk is the
APK; the process is the forked, specialised Zygote child. This is covered properly in
[09-Android-App-Internals](../09-Android-App-Internals/README.md).

> **📖 Definition** — **Process**: an executing instance of a program, holding a private address
> space and the kernel bookkeeping that goes with it. The unit of isolation in the Android sandbox is
> the process's UID, not the program file.

### Is a thread just a small process?

Not quite, and the difference is exactly the thing that makes concurrency bugs into security bugs. A
thread is a schedulable stream of execution. A process contains at least one thread and may contain
hundreds. What makes threads different from processes is what they share and what they do not.

| Resource | Separate per thread | Shared across threads in a process |
|---|---|---|
| Program counter and registers | Yes | — |
| Stack | Yes | — |
| Thread ID (TID) | Yes | — |
| Signal mask | Yes | — |
| Thread-local storage | Yes | — |
| Virtual address space and page tables | — | Yes |
| Heap | — | Yes |
| Global and static variables | — | Yes |
| Open file descriptors | — | Yes |
| UID, GID, and SELinux context | — | Yes |
| Loaded shared libraries | — | Yes |

On Linux the kernel does not really distinguish the two at all: both are created by the `clone`
syscall, and the flags passed to `clone` decide how much is shared. `fork()` calls `clone` with
almost nothing shared; `pthread_create()` calls `clone` with `CLONE_VM | CLONE_FS | CLONE_FILES |
CLONE_SIGHAND | CLONE_THREAD` and friends, so the new task shares the address space. The kernel calls
both a "task". The process ID you see is really the thread group ID (`Tgid`), and the individual
thread IDs live under `/proc/<pid>/task/`.

The security consequence is that shared memory plus independent scheduling equals races. Two threads
writing the same variable without synchronisation can interleave in ways neither author considered,
which is where time-of-check-to-time-of-use bugs come from. Two processes cannot do this to each
other's memory, which is why the process boundary — not the thread boundary — is the security
boundary in Android.

### What is a race condition and why is it a security bug?

A race condition is a defect where the correctness of the program depends on the relative timing of
two or more concurrent operations, and the programmer assumed one ordering while the scheduler is
free to produce another. The canonical example is a non-atomic increment: `counter = counter + 1`
compiles to a load, an add, and a store, and if two threads run those six instructions interleaved,
one increment can be silently lost.

It becomes a security bug when the racing operations are a security check and the action that the
check was supposed to protect. This pattern has a name, time-of-check to time-of-use (TOCTOU). A
program checks that a path is not a symbolic link, and then opens it; between the check and the open,
an attacker replaces the path with a symlink to `/data/data/com.victim/shared_prefs/secrets.xml`, and
the program opens a file it just proved it should not. The check was true when it ran. It was false
when it mattered.

```c
// vulnerable pattern — check and use are separate operations
if (access(path, W_OK) == 0) {   // time of check
    int fd = open(path, O_WRONLY); // time of use — path may now be a symlink
    write(fd, data, len);
}
```

Races are hard to find and harder to reproduce, because the bad interleaving may occur once in
thousands of runs on your device and constantly on a device with different core counts. That is also
why they get shipped: the developer's test passed. When you find one during an engagement, prove it
with a loop that hammers the operation rather than a single manual attempt, and report the
interleaving explicitly rather than saying "it sometimes fails".

> **⚠️ Warning** — "It only happened once" is not evidence that a race is unexploitable. Attackers
> can widen the window deliberately, for example by forcing page faults, by pinning threads to
> specific cores, or by inflating the file the victim reads.

---

## Memory: the stack and the heap

### Why does the stack grow downward?

Mostly for a historical layout reason that has become a hardware and ABI convention. In the classic
single-address-space layout, the program's code and static data sit at low addresses, the heap grows
upward from just above them, and the stack starts at the top of the usable address space and grows
downward. Putting them at opposite ends means each region can expand into the shared middle without
either one needing to know in advance how large the other will get. With a 64-bit address space this
is no longer a scarcity problem, but the convention is baked into every ABI, every unwinder, and the
AArch64 instruction set's addressing habits, so it stays.

Concretely, on AArch64 "pushing" means subtracting from the stack pointer. The function prologue
`stp x29, x30, [sp, #-32]!` subtracts 32 from `SP` and stores the frame pointer and link register at
the new, lower address. Popping adds back. Because `SP` moves toward lower addresses as the call depth
grows, a deeply recursive function eventually walks `SP` into a `PROT_NONE` guard page below the stack
mapping and the process dies with `SIGSEGV` instead of quietly stomping on the heap.

The direction matters for exploitation in one crucial way. Local buffers are written *upward*, from
low addresses to high, but the saved frame pointer and saved link register sit *above* the locals in
the same frame. So a buffer that is overflowed in the normal direction — the direction `memcpy` and
`strcpy` write — runs straight into the saved return address. Stack layout and copy direction
conspire, which is precisely why stack buffer overflows became the archetypal exploit.

### What is the difference between the stack and the heap and why does it matter for bugs?

They are two regions of a process's memory with different management policies. The stack is managed
automatically by the compiler in strict last-in-first-out order tied to function calls; allocation is
one instruction that adjusts `SP`, and deallocation is automatic at function return. The heap is
managed explicitly at runtime by an allocator library; you ask for memory with `malloc` or `new` and
you must give it back with `free` or `delete`, and blocks may be freed in any order.

| Property | Stack | Heap |
|---|---|---|
| Managed by | Compiler and CPU, via `SP` | Allocator in libc, on request |
| Allocation cost | One arithmetic instruction | Bookkeeping, free-list search, sometimes a syscall |
| Lifetime | Bound to the enclosing function call | Whatever the programmer decides |
| Size limit | Small and fixed, typically 1 MiB per thread on Android | Large, grows via `mmap` |
| Fragmentation | None | Yes, both internal and external |
| Typical contents | Locals, saved registers, spilled arguments | Objects, buffers, anything sized at runtime |
| Thread relationship | One per thread, private | Shared by all threads |
| Classic bugs | Stack buffer overflow, uninitialised locals, stack exhaustion | Heap overflow, use-after-free, double free, leaks |

It matters for bugs because the two regions fail in different ways and are exploited with different
techniques. On the stack, the interesting target lies at a fixed offset from the overflowed buffer:
the saved link register, whose value the CPU will branch to at `ret`. Corrupt it and you control the
program counter directly. Mitigations therefore focus on that one target — stack canaries detect the
overwrite, and the shadow call stack keeps an uncorrupted copy of the return address in a region
reached through `X18`.

On the heap, there is no fixed target. What sits after your buffer depends on what the allocator gave
out and in what order, so heap exploitation is about *shaping* the heap: making the allocator place a
juicy object — one containing a function pointer, a length field, or a C++ vtable pointer — directly
after the buffer you can overflow. That is why heap bugs feel much harder at first and why heap
exploitation write-ups spend most of their length on grooming rather than on the overflow itself.
[19-Memory](../19-Memory/README.md) goes through both in detail.

### What is a segfault really?

A segmentation fault is the process's death certificate, signed by the memory management unit. When
your code touches a virtual address, the MMU walks the page tables to translate it into a physical
address. If there is no valid translation, or the translation exists but forbids the kind of access
you attempted, the hardware raises an exception and traps into the kernel. The kernel looks at the
faulting address, decides whether it can fix things — for example by paging in a file-backed page, or
by allocating a zero page for a first touch, or by copying a copy-on-write page — and if it cannot, it
delivers `SIGSEGV` to the offending thread. The default action for `SIGSEGV` is to terminate the
process and write a core dump, which on Android becomes a tombstone in `/data/tombstones/`.

Two subcodes tell you which of the two failures happened, and they mean very different things during
an assessment.

| `si_code` | Name | Meaning | Typical cause |
|---|---|---|---|
| 1 | `SEGV_MAPERR` | No mapping at that address | Null or wild pointer, use of a freed-and-unmapped region |
| 2 | `SEGV_ACCERR` | Mapped, but permissions deny the access | Writing to `.rodata`, executing a non-executable page |

The distinction matters because `SEGV_ACCERR` on an execute attempt means control flow already
reached an address you may control, which is a much stronger signal than a read of address zero. The
faulting address is printed in the tombstone along with the full register set, so you can see whether
the address came from attacker-controlled data — for example, `0x4141414141` after sending a string of
`A` characters.

> **🔬 Under the Hood** — A `SIGSEGV` is not an error the kernel invented; it is the kernel's
> translation of a hardware exception it decided not to resolve. The same mechanism, when the kernel
> *does* resolve it, is ordinary demand paging that happens millions of times per second without
> anyone noticing.

### What is a null pointer dereference?

A pointer is a variable whose value is a memory address. The null pointer is the value zero, used
universally to mean "this pointer refers to nothing", and dereferencing it means trying to read or
write the memory at address zero as though it held a real object. Operating systems deliberately
leave the lowest part of the address space unmapped precisely so that this mistake crashes loudly
rather than corrupting something. On Linux the minimum mappable address is controlled by
`/proc/sys/vm/mmap_min_addr`, which is non-zero on any modern Android device.

In practice you meet null dereferences as a crash with a fault address that is zero or a small value.
A small non-zero fault address is a strong hint about the bug: it usually means the code dereferenced
a null *struct* pointer and then accessed a field at some offset, so the fault address is the field
offset. A crash at `0x28` tells you a field 40 bytes into a structure was touched through a null base
pointer, which often narrows the culprit to a single line.

For severity, a plain null dereference in an app process is usually a denial of service and nothing
more, because address zero is unmappable and cannot be primed with attacker data. Treat it as a
reliability bug unless it is reachable from another application through an exported component, in
which case a remotely triggerable crash of a privileged process may be worth reporting on its own. In
the kernel, historically, null dereferences were far more serious because a process could once map
page zero; that is what `mmap_min_addr` exists to prevent.

### What is a use-after-free?

A use-after-free is what happens when a program keeps using a pointer to memory it has already
returned to the allocator. The `free()` call does not erase anything and does not make your pointer
null; it simply tells the allocator that the block is available again. Your pointer still holds the
same address and still points at bytes that look plausible. The program keeps working, right up until
the allocator hands that same block to a different part of the program.

That is where it becomes a security bug rather than a latent one. Suppose a `Session` object is freed
while a stale pointer to it survives. Later the app allocates a `Buffer` of the same size, and the
allocator reuses the exact block. Now the stale `Session*` and the live `Buffer*` alias the same
bytes. Writing to the buffer with attacker-controlled data overwrites the fields of a `Session` that
some other code still believes is valid — including, in C++, the vtable pointer at offset zero, which
the next virtual method call will dereference and branch through. That is a direct route from a
lifetime mistake to controlled execution.

```c
// the shape of the bug
struct session *s = malloc(sizeof *s);
free(s);              // block returns to the allocator
/* ... other code allocates a same-sized block and fills it ... */
s->is_admin = 1;      // use-after-free: writing into someone else's object
```

Defences work at three levels. Programmers avoid it with ownership discipline — smart pointers in
C++, setting pointers to null after freeing, avoiding raw pointers across lifetimes. Allocators make
reuse less predictable and add quarantine delays, which is part of what Scudo does on Android.
Hardware makes it detectable: ARM's Memory Tagging Extension tags each 16-byte granule and each
pointer, so a stale pointer's tag no longer matches after reuse and the access faults immediately.
[19-Memory](../19-Memory/README.md) covers detection with HWASan and MTE in depth.

---

## Virtual memory and addresses

### Why do addresses change every time I run the program?

That is Address Space Layout Randomisation working as designed. If the stack, the heap, the mapped
libraries, and the executable itself always landed at the same addresses, an attacker who found a
buffer overflow would also know exactly what address to jump to, and a single exploit would work
identically on every device. ASLR randomises those base addresses at process creation, so the
attacker must first *discover* an address at runtime through an information leak before they can use
one. It does not fix any bug; it raises the cost of exploiting every bug.

For it to cover the main executable as well as the libraries, the executable must be position
independent, which is what the PIE flag means. Android has required position-independent executables
since Android 5.0, and every `.so` is position independent by construction, so on a modern device all
of the interesting regions move. You can watch this yourself:

```bash
# adb shell — runs on the device, as root
cat /proc/$(pidof com.example.app)/maps | head -5
# kill and restart the app, then run it again — the base addresses differ
```

Two Android-specific wrinkles are worth knowing. First, processes forked from Zygote inherit Zygote's
address space layout, so the preloaded framework libraries sit at the same addresses in every app
until the Zygote itself is restarted. Second, ASLR randomises *bases*, not internal layout: the offset
of a function within `libc.so` is constant, so leaking any single address inside a library gives you
every other address in it by subtraction. That is exactly how real exploits use an info leak, and it
is why a seemingly harmless address disclosure is a genuine finding.

> **🔍 Pentester's Note** — Practically, ASLR means you must never hardcode an address in a Frida
> script. Resolve it at runtime with `Module.findBaseAddress("libfoo.so")` and add the offset you
> found statically. See [53-Frida](../53-Frida/README.md).

### What is a page and why 4096 bytes?

A page is the fixed-size unit in which the kernel and the MMU manage memory. Rather than tracking
permissions and physical locations for every individual byte — which would need a translation table
larger than the memory it describes — the hardware divides the address space into equal blocks and
tracks one entry per block. A virtual address then splits cleanly into a page number, used to index
the page tables, and an offset within the page, which passes through translation untouched.

Four kibibytes is a compromise that stuck. Smaller pages waste less memory when a program needs only
a little (internal fragmentation) but require more page table entries and more TLB pressure. Larger
pages translate faster and need smaller tables but waste more on small allocations. With a 4 KiB
granule and 48-bit virtual addresses, AArch64 uses four levels of nine index bits each plus the
twelve offset bits, which is a tidy arrangement the hardware is built around. The arithmetic is also
trivial in binary: with 4096 = 2^12, the offset is the low twelve bits, so `addr & 0xFFF` is the
offset and `addr & ~0xFFF` is the page base.

It is not the only option, and this now matters on Android. Android 15 added support for devices with
16 KiB pages, and native libraries that assumed 4 KiB — for example by hardcoding page arithmetic or
by having `LOAD` segments aligned to only 4 KiB — fail to load on such devices. If you are testing an
app with native code, checking segment alignment is a legitimate compatibility and robustness finding.
ARM also supports huge pages of 2 MiB and 1 GiB with the 4 KiB granule, used mostly by the kernel and
by very large allocations.

```bash
# adb shell — confirm the page size on the device under test
getconf PAGE_SIZE
```

### What does `mmap` actually do and why does Frida care?

`mmap` asks the kernel to create a new mapping in the calling process's virtual address space. You
give it a length, a set of protection bits (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`), flags saying
whether the mapping is private or shared and whether it is backed by a file or by nothing at all, and
optionally a file descriptor and offset. The kernel installs a virtual memory area describing that
range and returns the address. Crucially, it does not usually allocate any physical memory yet — the
pages materialise on first touch, via page faults. That is why a process can map far more memory than
the device physically has.

Almost everything is built on it. Loading a shared library is a sequence of `mmap` calls, one per
`PT_LOAD` segment, with the code segment mapped read-execute from the file and the data segment
mapped read-write and private so that writes stay local. `malloc` gets its arenas from anonymous
`mmap`. Thread stacks are `mmap` regions with a `PROT_NONE` guard page below them. Shared memory
between processes is a shared `mmap` of the same object. Reading a large file with `mmap` instead of
`read` avoids a copy entirely.

Frida cares for two connected reasons. To run its own code inside a target process, it must first
obtain memory in that process, which means making the target call `mmap` — and then it must make that
memory executable, which means `mprotect` with `PROT_EXEC`. Instrumentation engines typically write
their generated trampolines and relocated instructions into a region while it is writable, then flip
it to read-execute, because keeping memory simultaneously writable and executable is both a hardening
violation and, on some systems, forbidden outright. This is also the detection angle: an app that
scans `/proc/self/maps` for anonymous `rwxp` regions, or for regions whose contents do not match the
file they claim to come from, is looking for exactly this footprint.

```bash
# adb shell — as root: look for suspicious executable anonymous mappings
grep -E 'rwxp|r-xp .*\[anon' /proc/$(pidof com.example.app)/maps
```

---

## The kernel and system calls

### What is a syscall and how is it different from a function call?

A function call is a branch within your own process. On AArch64 the `BL` instruction stores the
address of the next instruction in `X30` and jumps to the target; the target runs at the same
privilege level, in the same address space, with access to exactly the same memory you had. Nothing
about the machine's state or trust level changes. It costs a handful of cycles.

A system call is a request for the kernel to do something your process is not permitted to do itself.
It is implemented as a deliberate exception: you place the syscall number in `X8`, the arguments in
`X0` through `X5`, and execute `SVC #0`. The CPU switches from EL0 to EL1, saves the return state in
`ELR_EL1` and `SPSR_EL1`, and jumps to the kernel's fixed exception vector. The kernel dispatches on
the number, validates every pointer you passed — it must never trust a user-supplied address —
performs the operation, and returns either a result or a negative error code in `X0`. The libc
wrapper turns a negative return into `-1` plus a thread-local `errno`.

| Aspect | Function call | System call |
|---|---|---|
| Instruction | `BL` / `BLR` | `SVC #0` |
| Privilege change | None | EL0 to EL1 and back |
| Address space | Same | Kernel's, with careful access to yours |
| Argument passing | `X0`–`X7` per AAPCS64 | `X0`–`X5`, number in `X8` |
| Error reporting | Whatever the API defines | Negative errno in `X0`, converted by libc |
| Cost | Tens of cycles | Hundreds to thousands of cycles |
| Can be filtered | No | Yes, by seccomp |
| Observable with | `ltrace`, hooking the PLT | `strace`, seccomp logs |

The practical consequence for testing is that the syscall boundary is the one place where an app
cannot lie to you. An app can implement its own file access, its own string comparison, and its own
crypto, but if it opens a file it must eventually call `openat`, and if it connects to a server it
must eventually call `connect`. Tracing at that boundary sees through obfuscation that defeats
source-level or Java-level analysis.

### Why is there a kernel at all?

Because the alternative does not work once you have more than one program. Consider what has to be
true on a phone: two apps run at once and neither may read the other's memory; a malicious app must
not be able to read your photos; a buggy app must not be able to hang the device; and all of them
need to use one screen, one radio, and one flash chip without corrupting each other's data. Every one
of those requirements is a statement that somebody must arbitrate, and that arbitrator must be more
privileged than the programs it arbitrates.

The kernel is that arbitrator, and the hardware enforces its privilege. The CPU runs application code
at EL0, where the instructions that configure the MMU, mask interrupts, or access other exception
levels' system registers simply do not work. Only code at EL1 can change the page tables, so only the
kernel can decide which physical memory a process is allowed to see. Because the kernel controls the
page tables, process isolation is not a promise the apps make to each other — it is a property of the
address translation hardware that apps cannot opt out of.

Everything Android's security model claims rests on this. The app sandbox is per-app UIDs plus
kernel-enforced file permissions plus SELinux policy, all evaluated in kernel code. Binder, the
mechanism through which almost all Android IPC flows, is a kernel driver precisely because the kernel
is the only party both sides can trust to identify the caller honestly. This is why a kernel
vulnerability is categorically worse than an app vulnerability: it does not bypass one control, it
invalidates the foundation all the controls stand on. See
[20-Security-Architecture](../20-Security-Architecture/README.md) and
[21-App-Sandbox](../21-App-Sandbox/README.md).

---

## CPU, code, and binaries

### What is a register and how many are there?

A register is a storage location inside the CPU itself, as opposed to in RAM. It is the fastest
storage in the machine by a wide margin — access takes a fraction of a cycle, while a miss all the way
to DRAM costs hundreds — and it is where arithmetic actually happens. AArch64 instructions cannot add
two values in memory; they load into registers, operate on registers, and store back. That is what
makes ARM a load-store architecture.

AArch64 has 31 general-purpose registers, named `X0` through `X30` when used as 64-bit values and `W0`
through `W30` when used as their lower 32 bits. Writing to a `W` register zeroes the upper 32 bits of
the corresponding `X` register, which is a detail that catches people out when reading disassembly.
Register number 31 is context dependent: in most instructions it means the zero register `XZR`, which
reads as zero and discards writes, while in stack-addressing instructions it means `SP`. There are
also 32 SIMD and floating-point registers `V0`–`V31`, the program counter, and a large set of system
registers.

What matters more than the count is that the ABI assigns each register a role, and that role is how
you read disassembly. `X0`–`X7` carry the first eight arguments and `X0` carries the return value, so
the instruction before a `BL` tells you what is being passed. `X30` is the link register holding the
return address. `X29` is the frame pointer. `X19`–`X28` are callee-saved, so a function that uses them
must restore them. And on Android specifically, `X18` is reserved for the shadow call stack and must
never be clobbered. The full table is in [cheatsheet.md](cheatsheet.md) and the working detail is in
[18-ARM](../18-ARM/README.md).

### Do I need to learn assembly?

You need to be able to *read* it. You almost certainly do not need to write it. Those are very
different skill levels, and conflating them is why people avoid the topic for years longer than
necessary.

Reading means: given twenty lines of AArch64 disassembly from Ghidra or `objdump`, you can say what
the function does at the level of "it compares the length in `W1` against 0x20, and if it is greater
it branches to the error path, otherwise it calls `memcpy` with the destination in `X0`". To do that
you need the register roles, maybe thirty instruction mnemonics, the branch and condition codes, and
the prologue and epilogue patterns. That is a weekend of study and it is the single highest-leverage
thing you can learn for native Android work, because decompilers fail exactly on the code that matters
most — obfuscated routines, hand-written crypto, anti-tamper checks — and when the decompiler output
is nonsense the disassembly is still true.

Writing assembly is a different matter, and you will need it only in narrow situations: crafting a
small shellcode payload, writing a hook trampoline by hand, or patching an instruction to invert a
branch. Even then you will normally write one or two instructions, assemble them with a tool, and
patch the bytes, rather than authoring functions.

> **🧠 Mental Model** — Assembly is a language you read like a foreign-language menu, not one you
> compose poetry in. Recognition, not fluency, is the goal.

### Compiled vs interpreted vs JIT vs AOT — where does Android sit?

The four terms describe *when* source code becomes machine instructions. A traditional compiler
translates everything ahead of time, before the program ever runs, producing a native binary; C and
C++ through the NDK work this way and produce ELF `.so` files. An interpreter never translates at all:
it reads each instruction of the program and simulates its effect, every time it executes. Just-in-time
compilation is a hybrid — the program starts interpreted, the runtime notices which methods are hot,
and it compiles those to native code while the program runs. Ahead-of-time compilation in a managed
runtime means translating the bytecode to native code before execution, but at install or idle time
rather than at build time.

Android uses all four simultaneously, which is the honest answer.

| Layer | Model | Mechanism |
|---|---|---|
| Kotlin and Java source | Compiled to bytecode | `kotlinc`/`javac` then `d8`/`r8` produce DEX |
| DEX bytecode, cold methods | Interpreted | The ART interpreter executes DEX directly |
| DEX bytecode, hot methods | JIT | ART's JIT compiles them at runtime and records a profile |
| DEX bytecode, profiled methods | AOT | `dex2oat` compiles them to native code in an OAT file, typically during device idle |
| NDK C and C++ code | Compiled ahead of time | `clang` produces native `.so` files loaded by the linker |

Historically this changed a lot: Dalvik was JIT-only from Android 2.2, ART in Android 5.0 was AOT-only
and compiled everything at install time, and Android 7.0 introduced the profile-guided hybrid that is
still the model today. The security consequence is that "the code" of an Android app exists in several
forms at once — DEX in the APK, native code in an OAT file, JIT-generated code in an RWX region — and
your analysis has to name which one it is talking about. [11-Android-Runtime](../11-Android-Runtime/README.md)
and [13-ART](../13-ART/README.md) cover this properly.

### What is an ELF file and does Android use it?

ELF stands for Executable and Linkable Format, and it is the container format Unix-like systems use
for executables, shared libraries, object files, and core dumps. A file is ELF if its first four bytes
are `7F 45 4C 46`, which is `\x7F` followed by the ASCII letters `E`, `L`, `F`. The header that
follows says whether it is 32-bit or 64-bit, which byte order it uses, which machine it targets
(`0xB7` for AArch64), what type of object it is, and where to find the two tables that describe its
contents.

Those two tables serve different audiences, and understanding that split removes most of the
confusion. The *program header table* describes segments and is what the loader reads: each `PT_LOAD`
entry says "map this range of the file at this virtual address with these permissions". The *section
header table* describes sections such as `.text`, `.rodata`, `.data`, `.dynsym`, and `.got`, and is
what linkers and analysis tools read. Sections can be stripped from a shipped library without
affecting whether it loads, which is exactly why release builds are stripped and why your symbol names
are missing when you open a library in Ghidra.

Android uses ELF everywhere native code is involved: every `.so` inside `lib/arm64-v8a/` in an APK,
every binary in `/system/bin/`, the dynamic linker `/system/bin/linker64` itself, and the OAT files
ART produces — those are ELF files with the compiled code and metadata stored in custom sections. What
is *not* ELF is the DEX file, which is Android's own format with its own magic `dex\n035\0`, and the
APK, which is a ZIP archive starting with `PK\x03\x04`. Being able to identify all three by their
first bytes is a genuinely useful reflex.

```bash
# runs on your host machine
file lib/arm64-v8a/libnative.so
readelf -h lib/arm64-v8a/libnative.so | head -12
readelf -d lib/arm64-v8a/libnative.so | grep -E 'NEEDED|SONAME|BIND_NOW'
```

[15-Native-Code](../15-Native-Code/README.md) turns this into a hardening checklist covering PIE, NX,
RELRO, stack canaries, and FORTIFY.

---

## Odds and ends

### What is a file descriptor and why do people care about leaked ones?

A file descriptor is a small non-negative integer that a process uses to refer to something the kernel
opened on its behalf. It is an index into a per-process table, and each entry points at a kernel
object with its own offset and access mode. Descriptors 0, 1, and 2 are conventionally standard input,
standard output, and standard error. The abstraction is deliberately broad: regular files, directories,
pipes, sockets, `eventfd` objects, `memfd` regions, ashmem regions, and the `/dev/binder` device are
all reached through descriptors, which is what the phrase "everything is a file" actually means.

Two properties make descriptors security-relevant. First, they carry their access rights with them:
once a descriptor is open, the kernel does not re-check the path permissions on every read, so holding
the descriptor *is* the permission. Second, they can be inherited. A child created by `fork` gets a
copy of the whole table unless a descriptor was opened with `O_CLOEXEC`, and on Android a descriptor
can be sent to a completely unrelated process over Binder as a `ParcelFileDescriptor`.

Put those together and you get the leaked-descriptor bug class. A privileged process opens a sensitive
file, then passes a descriptor to a less privileged process — or forks a helper that inherits one it
was never meant to have — and the receiving process can now read or write a file its own UID and
SELinux context would never have permitted it to open. Checking `ls -l /proc/<pid>/fd` on an app
process during an assessment sometimes finds exactly this, and it is a good habit precisely because
it is cheap.

### Why does everyone keep saying "the stack is per-thread but the heap is shared"?

Because it explains which bugs are possible where, and it is the fastest way to reason about a crash
you did not expect. Each thread needs its own call chain, so each thread gets its own stack mapping —
typically about 1 MiB on Android, allocated with `mmap` and fronted by a `PROT_NONE` guard page. No
other thread's function calls touch it, which is why a local variable is automatically thread-safe and
why "make it a local" is the standard fix for a data race on a static.

The heap is one shared resource for the whole process, so two threads calling `malloc` at the same
time are contending for the same allocator. Modern allocators reduce that contention with per-thread
caches and multiple arenas, but the memory handed out is still visible to every thread, which is
precisely why a pointer stored in a global can be freed by one thread and used by another. Almost
every use-after-free with a race component has this shape.

The practical consequence when reading a crash: if the faulting address is close to a thread's stack
region in the memory map, you are looking at a stack problem, and the corrupted thing is probably a
saved register or return address. If it is inside a `[anon:libc_malloc]` or `[anon:scudo:...]` region,
you are looking at a heap problem, and the corrupted thing is probably allocator metadata or a
neighbouring object.

### If the kernel isolates processes, why do apps still get compromised?

Because isolation stops one app from reading another app's memory, and that is not the only thing that
can go wrong. The overwhelming majority of real mobile findings never cross a process boundary at all.
An app that stores a session token in world-readable shared preferences, disables certificate
validation, ships a hardcoded API key, or exports an activity that accepts an attacker-supplied URL
has a serious problem that no amount of kernel-enforced address space separation addresses, because
the app is doing exactly what it was told to do.

The kernel's guarantees are also only as strong as their configuration. Process isolation is enforced
per UID, so two apps signed with the same key and using `sharedUserId` historically shared one sandbox
by design. A file made world-readable is world-readable no matter how good the MMU is. A Binder
interface that does not check the caller's permission will happily serve any caller. And an app that
runs its own attacker-controlled input through native code with a heap overflow is compromised inside
its own sandbox, where the kernel has nothing to say.

> **🧠 Mental Model** — The kernel guarantees that a process cannot reach *outside* itself without
> permission. It guarantees nothing about what a process does to itself, or about what it voluntarily
> hands out. Most of your findings will live in that second category.

### Is it worth learning C if I only test apps?

Yes, at the level of reading rather than writing, for the same reason as assembly. Android's entire
lower half is C and C++: bionic, the ART runtime, the media stack, the crypto libraries, the Binder
driver, and any native library an app ships. When you want to know what `openat` returns on failure,
or what `libc`'s `strcpy` does when the destination is too small, or how a JNI function receives its
arguments, the answer is in C source you can read on your own machine.

More importantly, the memory-safety bug classes that this chapter keeps referring to are *artefacts of
C's model*. C gives you raw pointers, manual lifetimes, and no bounds checking, and use-after-free,
double free, and buffer overflow are the direct consequences. You cannot really understand why those
bugs exist, or why Rust and MTE are being introduced across AOSP, without having seen the model that
permits them. A weekend spent writing a program that deliberately overflows a stack buffer and then
watching it die under `gdb` teaches more than any amount of reading.

You do not need to become a C programmer. Aim for: read a function and follow the pointers, recognise
the unsafe standard library calls (`strcpy`, `strcat`, `sprintf`, `gets`, unbounded `memcpy` with a
computed length), and be able to write a thirty-line test harness that calls a function out of a
library you are auditing. [03-Programming-Fundamentals](../03-Programming-Fundamentals/README.md)
starts that path.
