# 01 — Computer Science Basics · Cheat Sheet

> Printable reference. Tables and commands only.
> Companion to [README.md](README.md) · [mindmap.md](mindmap.md) · [faq.md](faq.md)
> Deeper: [18-ARM](../18-ARM/README.md) · [19-Memory](../19-Memory/README.md) · [15-Native-Code](../15-Native-Code/README.md)

---

## 1. Number bases — decimal / binary / hex / ASCII

| Dec | Binary (4-bit) | Hex | ASCII (printable) | Note |
|---|---|---|---|---|
| 0 | `0000` | `0x00` | `NUL` | string terminator in C |
| 1 | `0001` | `0x01` | `SOH` | |
| 2 | `0010` | `0x02` | `STX` | |
| 3 | `0011` | `0x03` | `ETX` | |
| 4 | `0100` | `0x04` | `EOT` | |
| 5 | `0101` | `0x05` | `ENQ` | |
| 6 | `0110` | `0x06` | `ACK` | |
| 7 | `0111` | `0x07` | `BEL` | `\a` |
| 8 | `1000` | `0x08` | `BS` | `\b` |
| 9 | `1001` | `0x09` | `TAB` | `\t` |
| 10 | `1010` | `0x0A` | `LF` | `\n` — Unix newline |
| 11 | `1011` | `0x0B` | `VT` | |
| 12 | `1100` | `0x0C` | `FF` | |
| 13 | `1101` | `0x0D` | `CR` | `\r` |
| 14 | `1110` | `0x0E` | `SO` | |
| 15 | `1111` | `0x0F` | `SI` | one hex digit = one nibble |
| 16 | `0001 0000` | `0x10` | `DLE` | |

| Value | Hex | Binary | Meaning you will actually meet |
|---|---|---|---|
| 32 | `0x20` | `0010 0000` | ASCII space; bit 5 = ASCII case bit |
| 48 | `0x30` | `0011 0000` | ASCII `'0'` (digits `0x30`–`0x39`) |
| 65 | `0x41` | `0100 0001` | ASCII `'A'` (`A`–`Z` = `0x41`–`0x5A`) |
| 97 | `0x61` | `0110 0001` | ASCII `'a'` (`a`–`z` = `0x61`–`0x7A`) |
| 127 | `0x7F` | `0111 1111` | `DEL`; max signed 8-bit; last ASCII code point |
| 128 | `0x80` | `1000 0000` | min signed 8-bit (`-128`); first non-ASCII byte |
| 255 | `0xFF` | `1111 1111` | max unsigned byte; `-1` as `int8_t` |
| 256 | `0x100` | `1 0000 0000` | needs a 9th bit — byte overflow boundary |
| 4096 | `0x1000` | — | default page size |
| 65535 | `0xFFFF` | — | max unsigned 16-bit; max TCP port |
| 3735928559 | `0xDEADBEEF` | — | classic debug filler / poison value |
| 3405691582 | `0xCAFEBABE` | — | Java `.class` magic (big-endian on disk) |
| 2019914703 | `0x78563412` | — | `0x12345678` read with wrong endianness |
| — | `0x7F454C46` | — | ELF magic: `\x7F` `E` `L` `F` |
| — | `0x64 0x65 0x78` | — | DEX magic prefix `dex\n035\0` |
| — | `0x504B0304` | — | ZIP/APK local file header `PK\x03\x04` |
| — | `0xA5A5A5A5` | — | jemalloc/scudo-style free poison patterns |

| Conversion | Rule |
|---|---|
| Binary → hex | Group bits in 4s from the right, map each nibble |
| Hex → binary | Expand each hex digit to 4 bits |
| Hex digits per byte | 2 |
| Hex digits per 32-bit word | 8 |
| Hex digits per 64-bit address | 16 (Android userspace usually shows 12 significant) |
| Bits per hex digit | 4 |
| `0b` / `0x` / `0` prefixes | binary / hex / octal in C, Java, Kotlin, Python |

---

## 2. Powers of two

| Exponent | Value | Size name | Where it shows up |
|---|---|---|---|
| 2^0 | 1 | 1 B | |
| 2^1 | 2 | | |
| 2^2 | 4 | | `int` size (bytes) |
| 2^3 | 8 | | bits per byte; pointer size on LP64 |
| 2^4 | 16 | | AArch64 stack alignment |
| 2^5 | 32 | | AArch64 general-purpose register count |
| 2^6 | 64 | | cache line size on most ARM cores |
| 2^7 | 128 | | max signed byte + 1 |
| 2^8 | 256 | | values per byte |
| 2^9 | 512 | | classic disk sector |
| 2^10 | 1 024 | 1 KiB | |
| 2^11 | 2 048 | 2 KiB | |
| 2^12 | 4 096 | 4 KiB | **default page size** |
| 2^13 | 8 192 | 8 KiB | |
| 2^14 | 16 384 | 16 KiB | Android 15+ large page size |
| 2^15 | 32 768 | 32 KiB | max signed 16-bit + 1 |
| 2^16 | 65 536 | 64 KiB | ARM contiguous-PTE page; ELF max alignment on some ABIs |
| 2^20 | 1 048 576 | 1 MiB | |
| 2^21 | 2 097 152 | 2 MiB | ARM64 huge page (PMD, 4 KiB granule) |
| 2^24 | 16 777 216 | 16 MiB | common default Android heap growth step |
| 2^30 | 1 073 741 824 | 1 GiB | ARM64 huge page (PUD, 4 KiB granule) |
| 2^31 | 2 147 483 648 | 2 GiB | max signed 32-bit + 1 |
| 2^32 | 4 294 967 296 | 4 GiB | full 32-bit address space |
| 2^39 | 549 755 813 888 | 512 GiB | 3-level 4 KiB page table VA span |
| 2^40 | 1 099 511 627 776 | 1 TiB | |
| 2^48 | 281 474 976 710 656 | 256 TiB | common AArch64 VA size (`VA_BITS=48`) |
| 2^52 | 4 503 599 627 370 496 | 4 PiB | ARMv8.2 LVA VA size |
| 2^63 | 9 223 372 036 854 775 808 | | max signed 64-bit + 1 |
| 2^64 | 18 446 744 073 709 551 616 | 16 EiB | full 64-bit address space |

| Unit | Binary | Decimal (SI) |
|---|---|---|
| KiB / kB | 1 024 | 1 000 |
| MiB / MB | 1 048 576 | 1 000 000 |
| GiB / GB | 1 073 741 824 | 1 000 000 000 |

---

## 3. Two's complement

| Width | Unsigned range | Signed range | `-1` as hex |
|---|---|---|---|
| 8-bit | 0 … 255 | −128 … 127 | `0xFF` |
| 16-bit | 0 … 65 535 | −32 768 … 32 767 | `0xFFFF` |
| 32-bit | 0 … 4 294 967 295 | −2 147 483 648 … 2 147 483 647 | `0xFFFFFFFF` |
| 64-bit | 0 … 18 446 744 073 709 551 615 | −9 223 372 036 854 775 808 … 9 223 372 036 854 775 807 | `0xFFFFFFFFFFFFFFFF` |

| Bit pattern (8-bit) | Unsigned | Signed | Comment |
|---|---|---|---|
| `0000 0000` / `0x00` | 0 | 0 | |
| `0000 0001` / `0x01` | 1 | 1 | |
| `0111 1110` / `0x7E` | 126 | 126 | |
| `0111 1111` / `0x7F` | 127 | 127 | largest positive |
| `1000 0000` / `0x80` | 128 | −128 | sign bit set; `abs()` overflows here |
| `1000 0001` / `0x81` | 129 | −127 | |
| `1111 1110` / `0xFE` | 254 | −2 | |
| `1111 1111` / `0xFF` | 255 | −1 | `memset(p, 0xFF, n)` fills with −1 |

| Operation | Rule |
|---|---|
| Negate | Invert all bits, add 1 |
| Sign bit | Most significant bit (1 = negative) |
| Sign extension | Copy MSB leftwards (`SXTB`/`SXTW` on AArch64) |
| Zero extension | Fill left with 0 (`UXTB`, or any `W`-register write) |
| Classic bug | Signed `int` length compared with `<`, then used as unsigned `size_t` |

---

## 4. Data type sizes

| C type | LP64 (arm64-v8a, x86_64) | ILP32 (armeabi-v7a, x86) |
|---|---|---|
| `char` | 1 | 1 |
| `short` | 2 | 2 |
| `int` | 4 | 4 |
| `long` | **8** | **4** |
| `long long` | 8 | 8 |
| pointer `void*` | **8** | **4** |
| `size_t` / `uintptr_t` | 8 | 4 |
| `ssize_t` / `ptrdiff_t` | 8 | 4 |
| `off_t` (bionic, `_FILE_OFFSET_BITS=64`) | 8 | 8 |
| `float` | 4 | 4 |
| `double` | 8 | 8 |
| `long double` | 16 (quad on AArch64) | 8 (same as `double` on ARM32) |
| `jlong` / `jint` (JNI) | 8 / 4 | 8 / 4 |
| `_Bool` | 1 | 1 |

| Java / Kotlin primitive | Size | Range / note |
|---|---|---|
| `boolean` / `Boolean` | 1 byte in arrays, slot-sized on stack | JVM has no true 1-bit type |
| `byte` / `Byte` | 1 | signed −128 … 127 (no unsigned byte in Java) |
| `char` / `Char` | 2 | UTF-16 code unit, unsigned 0 … 65 535 |
| `short` / `Short` | 2 | signed |
| `int` / `Int` | 4 | signed, wraps silently on overflow |
| `long` / `Long` | 8 | signed |
| `float` / `Float` | 4 | IEEE-754 binary32 |
| `double` / `Double` | 8 | IEEE-754 binary64 |
| object reference | 4 with compressed refs, else 8 | ART uses 32-bit refs for heaps < 4 GiB |

| Alignment rule | Value |
|---|---|
| Natural alignment | Type size, up to 8 (16 for `long double`/`__int128` on AArch64) |
| AArch64 stack (`SP`) at public interface | 16 bytes |
| Struct size | Padded up to a multiple of its strictest member alignment |
| `alignof(max_align_t)` on LP64 | 16 |

---

## 5. Endianness

Value: **`0x12345678`** (32-bit), stored at address `0x1000`.

| Address | Little-endian byte | Big-endian byte |
|---|---|---|
| `0x1000` | `0x78` | `0x12` |
| `0x1001` | `0x56` | `0x34` |
| `0x1002` | `0x34` | `0x56` |
| `0x1003` | `0x12` | `0x78` |

| Context | Endianness |
|---|---|
| Android / ARM64 / x86_64 in practice | Little-endian |
| ARM architecture capability | Bi-endian (`SCTLR_EL1.EE`/`E0E`), Android always uses LE |
| Network byte order (IP, TCP, TLS) | Big-endian |
| Java `DataOutputStream`, `ByteBuffer` default | Big-endian |
| `ByteBuffer.order(ByteOrder.nativeOrder())` on Android | Little-endian |
| DEX file format | Little-endian (`endian_tag` `0x12345678` = `ENDIAN_CONSTANT`) |
| Java `.class` file format | Big-endian |
| ELF | Declared by `e_ident[EI_DATA]`: `1` = LSB, `2` = MSB |

---

## 6. AArch64 registers (AAPCS64)

| Register | 32-bit alias | AAPCS64 role | Volatile? |
|---|---|---|---|
| `X0`–`X7` | `W0`–`W7` | Argument 1–8; `X0`(–`X7`) also return value | Caller-saved |
| `X8` | `W8` | Indirect result location (`XR`); **Linux syscall number** | Caller-saved |
| `X9`–`X15` | `W9`–`W15` | Temporary / scratch | Caller-saved |
| `X16` | `W16` | `IP0` — intra-procedure-call scratch; PLT/linker veneers | Caller-saved |
| `X17` | `W17` | `IP1` — intra-procedure-call scratch | Caller-saved |
| `X18` | `W18` | Platform register; on Android = **Shadow Call Stack** pointer — never clobber | Reserved |
| `X19`–`X28` | `W19`–`W28` | Callee-saved general purpose | Callee-saved |
| `X29` | — | `FP` — frame pointer, head of the frame-record chain | Callee-saved |
| `X30` | — | `LR` — link register, return address written by `BL`/`BLR` | Caller-saved |
| `SP` | `WSP` | Stack pointer; 16-byte aligned at public interfaces | Special |
| `PC` | — | Program counter; not a general register, read via `ADR`/`ADRP` | Special |
| `XZR` | `WZR` | Zero register — reads 0, writes discarded (encoding 31) | Special |
| `V0`–`V7` | `Q/D/S/H/B` views | SIMD/FP arguments and return values | Caller-saved |
| `V8`–`V15` | | SIMD/FP; **low 64 bits** callee-saved | Partly callee-saved |
| `V16`–`V31` | | SIMD/FP temporaries | Caller-saved |

| NZCV flag | Bit | Set when |
|---|---|---|
| `N` | 31 | Result negative (MSB set) |
| `Z` | 30 | Result zero |
| `C` | 29 | Unsigned carry out / no borrow |
| `V` | 28 | Signed overflow |

> Condition codes (`EQ`, `NE`, `LT`, `GE`, `HI`, `LS`, …) and system registers (`ELR_ELn`,
> `TTBR0_EL1`, `TPIDR_EL0`) are tabulated in [18-ARM](../18-ARM/README.md).

| Exception level | Runs | Android example |
|---|---|---|
| `EL0` | Unprivileged | App process, Zygote children, `system_server` |
| `EL1` | OS kernel | Linux kernel, `binder` driver |
| `EL2` | Hypervisor | KVM, pKVM, Gunyah |
| `EL3` | Secure monitor | ARM Trusted Firmware; gateway to Secure world (`S-EL1` TEE OS) |

---

## 7. x86-64 registers (for comparison)

| Register | 32/16/8 aliases | System V AMD64 role |
|---|---|---|
| `RAX` | `EAX`/`AX`/`AL` | Return value; **syscall number**; varargs FP count |
| `RDI` | `EDI` | Argument 1 |
| `RSI` | `ESI` | Argument 2 |
| `RDX` | `EDX` | Argument 3; second return register |
| `RCX` | `ECX` | Argument 4 (function calls) — clobbered by `syscall` |
| `R10` | `R10D` | Argument 4 **for syscalls** (replaces `RCX`) |
| `R8` | `R8D` | Argument 5 |
| `R9` | `R9D` | Argument 6 |
| `R11` | `R11D` | Scratch; clobbered by `syscall` (holds saved `RFLAGS`) |
| `RBX`, `RBP`, `R12`–`R15` | | Callee-saved |
| `RSP` | `ESP` | Stack pointer |
| `RBP` | `EBP` | Frame pointer by convention |
| `RIP` | `EIP` | Instruction pointer; `RIP`-relative addressing |
| `RFLAGS` | `EFLAGS` | `ZF`, `SF`, `CF`, `OF`, `PF`, `DF` |

| Concept | AArch64 | x86-64 |
|---|---|---|
| Return address | `X30` (register) | pushed on stack by `CALL` |
| Syscall instruction | `SVC #0` | `SYSCALL` |
| Syscall number | `X8` | `RAX` |
| Syscall args | `X0`–`X5` | `RDI`,`RSI`,`RDX`,`R10`,`R8`,`R9` |
| Return value | `X0` | `RAX` |
| Instruction width | Fixed 4 bytes | Variable 1–15 bytes |
| Stack alignment | 16 | 16 at `CALL` site |

---

## 8. Linux syscalls (AArch64, `asm-generic` numbering)

> Authoritative list: kernel `include/uapi/asm-generic/unistd.h` (arm64 has no private table).
> Bionic wrappers are generated from `bionic/libc/SYSCALLS.TXT`.

| Syscall | arm64 `x8` | x86-64 `rax` | Purpose |
|---|---|---|---|
| `ioctl` | 29 | 16 | device control — **Binder uses this** |
| `faccessat` | 48 | 269 | permission check (root-detection favourite) |
| `openat` | 56 | 257 | open file (arm64 has **no** plain `open`) |
| `close` | 57 | 3 | close fd |
| `read` | 63 | 0 | read fd |
| `write` | 64 | 1 | write fd |
| `newfstatat` / `fstat` | 79 / 80 | 262 / 5 | stat by path / by fd |
| `exit` / `exit_group` | 93 / 94 | 60 / 231 | terminate thread / process |
| `futex` | 98 | 202 | userspace lock wait/wake |
| `ptrace` | 117 | 101 | debug/trace — **Frida, gdb, anti-debug** |
| `kill` / `tgkill` | 129 / 131 | 62 / 234 | signal a process / a thread |
| `rt_sigaction` | 134 | 13 | install signal handler |
| `prctl` | 167 | 157 | process control (`PR_SET_DUMPABLE`, `PR_SET_NO_NEW_PRIVS`) |
| `getpid` / `gettid` | 172 / 178 | 39 / 186 | process id / thread id |
| `getuid` / `geteuid` | 174 / 175 | 102 / 107 | user id — the app sandbox identity |
| `socket` / `connect` | 198 / 203 | 41 / 42 | create / connect socket |
| `brk` | 214 | 12 | legacy heap break |
| `munmap` / `mremap` | 215 / 216 | 11 / 25 | unmap / resize mapping |
| `clone` | 220 | 56 | create process or thread — backs `fork()` and `pthread_create()` |
| `execve` | 221 | 59 | replace process image |
| `mmap` | 222 | 9 | map memory or file |
| `mprotect` | 226 | 10 | change page permissions — **RW→RX for JIT/Frida** |
| `wait4` | 260 | 61 | wait for child |
| `process_vm_readv` / `writev` | 270 / 271 | 310 / 311 | cross-process memory access |
| `seccomp` | 277 | 317 | install syscall filter |
| `memfd_create` | 279 | 319 | anonymous file in memory |
| `openat2` | 437 | 437 | open with resolve flags |

| Path | What it holds |
|---|---|
| `include/uapi/asm-generic/unistd.h` | Canonical arm64 syscall numbers |
| `arch/arm64/include/asm/unistd32.h` | 32-bit compat (armeabi-v7a) numbers |
| `bionic/libc/SYSCALLS.TXT` | Bionic wrapper generation table |
| `bionic/libc/kernel/uapi/` | Sanitised kernel UAPI headers used by the NDK |

---

## 9. `mmap` / `mprotect` constants

| `prot` flag | Value | Meaning |
|---|---|---|
| `PROT_NONE` | `0x0` | No access — guard pages |
| `PROT_READ` | `0x1` | Readable |
| `PROT_WRITE` | `0x2` | Writable |
| `PROT_EXEC` | `0x4` | Executable |
| `PROT_GROWSDOWN` | `0x01000000` | Extend downward with the stack |
| `PROT_GROWSUP` | `0x02000000` | Extend upward |

| `flags` | Value | Meaning |
|---|---|---|
| `MAP_SHARED` | `0x01` | Writes visible to other mappers and the file |
| `MAP_PRIVATE` | `0x02` | Copy-on-write private mapping |
| `MAP_SHARED_VALIDATE` | `0x03` | Like `MAP_SHARED`, unknown flags rejected |
| `MAP_FIXED` | `0x10` | Map exactly at `addr`, replacing anything there |
| `MAP_ANONYMOUS` | `0x20` | Zero-filled, no backing file (`fd = -1`) |
| `MAP_GROWSDOWN` | `0x0100` | Stack-style mapping |
| `MAP_DENYWRITE` | `0x0800` | Ignored by modern kernels |
| `MAP_LOCKED` | `0x2000` | `mlock` the pages |
| `MAP_NORESERVE` | `0x4000` | No swap reservation |
| `MAP_POPULATE` | `0x8000` | Prefault page tables |
| `MAP_NONBLOCK` | `0x10000` | With `MAP_POPULATE`, do not block |
| `MAP_STACK` | `0x20000` | Suitable for a thread stack |
| `MAP_HUGETLB` | `0x40000` | Use huge pages |
| `MAP_FIXED_NOREPLACE` | `0x100000` | Fail with `EEXIST` instead of replacing |

| Common combination | Typical producer |
|---|---|
| `PROT_READ\|PROT_EXEC`, `MAP_PRIVATE\|MAP_FIXED` | Loaded `.so` text segment |
| `PROT_READ\|PROT_WRITE`, `MAP_PRIVATE\|MAP_ANONYMOUS` | malloc arena, thread stack |
| `PROT_NONE` | Guard page between thread stacks |
| `PROT_READ\|PROT_WRITE\|PROT_EXEC` (RWX) | JIT region, injected shellcode — a red flag when found in an app |
| `mprotect(..., PROT_READ\|PROT_EXEC)` after RW writes | ART JIT / Frida Gum committing generated code |

| `mmap` return | Meaning |
|---|---|
| Valid pointer | Success |
| `MAP_FAILED` = `(void*)-1` | Failure, check `errno` (`ENOMEM`, `EINVAL`, `EACCES`, `EPERM`) |

---

## 10. `errno` values

| Number | Name | Meaning |
|---|---|---|
| 1 | `EPERM` | Operation not permitted (capability/SELinux/`ptrace_scope`) |
| 2 | `ENOENT` | No such file or directory |
| 3 | `ESRCH` | No such process |
| 4 | `EINTR` | Interrupted by a signal — retry the call |
| 5 | `EIO` | I/O error |
| 7 | `E2BIG` | Argument list too long |
| 9 | `EBADF` | Bad file descriptor |
| 10 | `ECHILD` | No child processes |
| 11 | `EAGAIN` / `EWOULDBLOCK` | Try again / would block |
| 12 | `ENOMEM` | Out of memory |
| 13 | `EACCES` | Permission denied (DAC or SELinux) |
| 14 | `EFAULT` | Bad address — kernel refused your pointer |
| 16 | `EBUSY` | Resource busy |
| 17 | `EEXIST` | File exists |
| 20 | `ENOTDIR` | Not a directory |
| 21 | `EISDIR` | Is a directory |
| 22 | `EINVAL` | Invalid argument |
| 23 | `ENFILE` | System fd table full |
| 24 | `EMFILE` | Per-process fd limit reached |
| 28 | `ENOSPC` | No space left on device |
| 32 | `EPIPE` | Broken pipe (also raises `SIGPIPE`) |
| 38 | `ENOSYS` | Syscall not implemented / blocked by seccomp |
| 98 | `EADDRINUSE` | Address already in use |
| 104 | `ECONNRESET` | Connection reset by peer |
| 110 | `ETIMEDOUT` | Connection timed out |
| 111 | `ECONNREFUSED` | Connection refused |
| 113 | `EHOSTUNREACH` | No route to host |
| 115 | `EINPROGRESS` | Non-blocking connect in progress |

| Rule | Detail |
|---|---|
| Kernel ABI | Syscall returns `-errno` in `X0`; libc moves it into `errno` and returns `-1` |
| Thread safety | `errno` is thread-local (`__errno()` in bionic) |
| Only valid | After a call that actually failed — never test `errno` on success |
| Decode | `strerror(errno)`, `perror()`, `errno 13` (moreutils), `strace` prints it inline |

---

## 11. Signals

| No. | Name | Default action | Catchable | Typical cause |
|---|---|---|---|---|
| 2 | `SIGINT` | Terminate | Yes | Ctrl-C |
| 4 | `SIGILL` | Core | Yes | Illegal instruction; corrupted code page |
| 5 | `SIGTRAP` | Core | Yes | Breakpoint (`BRK #0`), single-step, `ptrace` stop |
| 6 | `SIGABRT` | Core | Yes | `abort()`, failed assert, libc heap corruption detection |
| 7 | `SIGBUS` | Core | Yes | Misaligned or unmapped-file access (`BUS_ADRALN`, `SIGBUS` on truncated `mmap`) |
| 8 | `SIGFPE` | Core | Yes | Integer divide by zero |
| 9 | `SIGKILL` | Terminate | **No** | `kill -9`, LMK/OOM killer, `ActivityManager` kill |
| 10 | `SIGUSR1` | Terminate | Yes | App-defined; ART uses signals for GC/checkpoints |
| 11 | `SIGSEGV` | Core | Yes | Invalid memory access — the crash you will see most |
| 12 | `SIGUSR2` | Terminate | Yes | App-defined |
| 13 | `SIGPIPE` | Terminate | Yes | Write to a closed socket/pipe |
| 14 | `SIGALRM` | Terminate | Yes | `alarm()` timer |
| 15 | `SIGTERM` | Terminate | Yes | Polite `kill` |
| 17 | `SIGCHLD` | Ignore | Yes | Child exited or stopped |
| 18 | `SIGCONT` | Continue | Yes | Resume a stopped process |
| 19 | `SIGSTOP` | Stop | **No** | Unconditional suspend |
| 20 | `SIGTSTP` | Stop | Yes | Ctrl-Z |
| 23 | `SIGURG` | Ignore | Yes | Out-of-band socket data |
| 29 | `SIGIO` / `SIGPOLL` | Terminate | Yes | Async I/O ready |
| 31 | `SIGSYS` | Core | Yes | Seccomp `SECCOMP_RET_TRAP` — blocked syscall |

| `SIGSEGV` `si_code` | Meaning |
|---|---|
| `SEGV_MAPERR` (1) | Address not mapped at all (classic null deref) |
| `SEGV_ACCERR` (2) | Mapped, but permissions forbid the access (write to `.rodata`, exec of NX page) |
| `SEGV_BNDERR` (3) | Bounds violation |
| `SEGV_MTEAERR`/`SEGV_MTESERR` (8/9) | ARM MTE tag mismatch (async/sync) |

> `kill -l` lists names and numbers. Fatal signals produce a tombstone in `/data/tombstones/`;
> `adb logcat -b crash` shows the summary.

---

## 12. ELF format

| `Elf64_Ehdr` field | Offset | Size | Contents |
|---|---|---|---|
| `e_ident[16]` | 0 | 16 | `7F 45 4C 46` + class/data/version/OSABI |
| `e_ident[EI_CLASS]` | 4 | 1 | `1`=ELF32, `2`=ELF64 |
| `e_ident[EI_DATA]` | 5 | 1 | `1`=little-endian, `2`=big-endian |
| `e_ident[EI_VERSION]` | 6 | 1 | `1` |
| `e_ident[EI_OSABI]` | 7 | 1 | `0`=System V, `3`=Linux |
| `e_type` | 16 | 2 | `1`=REL, `2`=EXEC, `3`=DYN (PIE/`.so`), `4`=CORE |
| `e_machine` | 18 | 2 | `0x28`=ARM(40), `0xB7`=AArch64(183), `0x03`=i386, `0x3E`=x86-64 |
| `e_version` | 20 | 4 | `1` |
| `e_entry` | 24 | 8 | Entry point virtual address |
| `e_phoff` | 32 | 8 | Program header table offset |
| `e_shoff` | 40 | 8 | Section header table offset |
| `e_flags` | 48 | 4 | Arch-specific flags |
| `e_ehsize` | 52 | 2 | 64 for ELF64, 52 for ELF32 |
| `e_phentsize` / `e_phnum` | 54 / 56 | 2 / 2 | Program header entry size / count |
| `e_shentsize` / `e_shnum` | 58 / 60 | 2 / 2 | Section header entry size / count |
| `e_shstrndx` | 62 | 2 | Index of section-name string table |

| Segment (`p_type`) | Value | Role |
|---|---|---|
| `PT_LOAD` | 1 | Mapped into memory by the loader |
| `PT_DYNAMIC` | 2 | Dynamic linking metadata |
| `PT_INTERP` | 3 | Path of the interpreter (`/system/bin/linker64`) |
| `PT_NOTE` | 4 | Notes, including build-id |
| `PT_PHDR` | 6 | The program header table itself |
| `PT_TLS` | 7 | Thread-local storage template |
| `PT_GNU_EH_FRAME` | `0x6474E550` | Unwind tables |
| `PT_GNU_STACK` | `0x6474E551` | Stack permissions — must not be `RWX` |
| `PT_GNU_RELRO` | `0x6474E552` | Region made read-only after relocation |

| Section | Contents | Typical permissions |
|---|---|---|
| `.text` | Machine code | `r-x` |
| `.rodata` | Constants, string literals | `r--` |
| `.data` | Initialised writable globals | `rw-` |
| `.bss` | Zero-initialised globals (no file bytes) | `rw-` |
| `.plt` | Procedure Linkage Table stubs | `r-x` |
| `.got` / `.got.plt` | Global Offset Table — hooking target | `rw-` (or `r--` with full RELRO) |
| `.dynamic` | `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, `DT_INIT` | `r--` |
| `.dynsym` / `.dynstr` | Exported/imported symbols and their names | `r--` |
| `.symtab` / `.strtab` | Full symbol table (stripped in release builds) | not loaded |
| `.rela.dyn` / `.rela.plt` | Relocations | `r--` |
| `.init` / `.fini` | Legacy init/teardown code | `r-x` |
| `.init_array` / `.fini_array` | Constructor/destructor pointers — run before `JNI_OnLoad` | `rw-` then RELRO |
| `.note.gnu.build-id` | Unique build hash for symbol matching | `r--` |
| `.comment` | Compiler version strings | not loaded |
| `.gnu.hash` / `.hash` | Symbol lookup acceleration | `r--` |

> Hardening markers (PIE, NX, RELRO, canaries, FORTIFY) and how to check each are tabulated in
> [15-Native-Code](../15-Native-Code/README.md).

---

## 13. Pages and virtual memory

| Fact | Value |
|---|---|
| Default page size | 4 KiB (`0x1000`) |
| Android 15+ large page option | 16 KiB (`0x4000`) — align ELF `LOAD` segments to 16 KiB |
| ARM64 huge pages (4 KiB granule) | 2 MiB (PMD), 1 GiB (PUD), 64 KiB contiguous PTE |
| Query at runtime | `getpagesize()`, `sysconf(_SC_PAGESIZE)`, `getconf PAGE_SIZE` |
| Page-align down | `addr & ~(pagesize - 1)` |
| Page-align up | `(addr + pagesize - 1) & ~(pagesize - 1)` |
| Page number / offset (4 KiB) | `addr >> 12` / `addr & 0xFFF` |
| Typical AArch64 VA size | 39, 48, or 52 bits (`CONFIG_ARM64_VA_BITS`) |
| Translation levels (4 KiB, 48-bit) | 4 (`L0`–`L3`), 9 index bits each + 12 offset bits |
| User vs kernel split | `TTBR0_EL1` (low, user) / `TTBR1_EL1` (high, kernel) |

| Term | One-line definition |
|---|---|
| MMU | Hardware unit translating virtual to physical addresses |
| Page table | Per-process tree of translation entries owned by the kernel |
| TLB | Cache of recent translations; flushed on switch unless ASID-tagged |
| Page fault | CPU exception when a translation is missing or forbidden |
| Minor / major fault | Served from RAM / requires storage or zram I/O |
| Copy-on-write | Shared page duplicated on first write — makes `fork()` and Zygote cheap |
| ASLR / KASLR | Randomised base addresses for userspace regions / for the kernel image |

| `/proc/<pid>/maps` permission column | Meaning |
|---|---|
| `r` | Readable |
| `w` | Writable |
| `x` | Executable |
| `-` | Permission absent |
| `p` | Private (copy-on-write) |
| `s` | Shared |

| Example map line | Reading |
|---|---|
| `7f8a1c0000-7f8a1e0000 r-xp 00000000 fd:00 1234 /system/lib64/libc.so` | libc code, execute-only-ish, private, file-backed |
| `7f8a1e0000-7f8a1e4000 r--p 00020000 fd:00 1234 /system/lib64/libc.so` | RELRO/rodata part of the same file |
| `7f8a200000-7f8a300000 rw-p 00000000 00:00 0 [anon:libc_malloc]` | Heap arena |
| `7fdd000000-7fdd020000 rw-p 00000000 00:00 0 [stack]` | Main thread stack |
| `7f9000000-7f9010000 rwxp 00000000 00:00 0 [anon:...]` | RWX region — JIT, or injected code |

---

## 14. `/proc` entries

| Path | Contents |
|---|---|
| `/proc/<pid>/maps` | Virtual memory map, one line per VMA |
| `/proc/<pid>/smaps` | Per-VMA RSS, PSS, dirty/clean, swap |
| `/proc/<pid>/smaps_rollup` | Aggregated totals for the whole process |
| `/proc/<pid>/status` | Name, State, Tgid, Pid, PPid, Uid, Gid, Threads, `Seccomp`, `TracerPid` |
| `/proc/<pid>/stat` | Machine-readable scheduler/CPU stats |
| `/proc/<pid>/statm` | Page counts: total, resident, shared, text, data |
| `/proc/<pid>/cmdline` | Argv, NUL-separated — the package name for an app |
| `/proc/<pid>/environ` | Environment variables, NUL-separated |
| `/proc/<pid>/fd/` | Symlinks for every open file descriptor |
| `/proc/<pid>/fdinfo/<n>` | Offset, flags, and driver-specific data per fd |
| `/proc/<pid>/task/<tid>/` | One directory per thread, each with its own `stat`/`status` |
| `/proc/<pid>/mem` | Raw address space (read/write via `ptrace` attach) |
| `/proc/<pid>/exe` | Symlink to the executable |
| `/proc/<pid>/cwd` / `root` | Working directory / filesystem root (namespace-aware) |
| `/proc/<pid>/auxv` | Auxiliary vector (`AT_PHDR`, `AT_ENTRY`, `AT_RANDOM`, `AT_HWCAP`) |
| `/proc/<pid>/limits` | `RLIMIT_*` soft/hard limits |
| `/proc/<pid>/oom_score_adj` | Low-memory-killer priority |
| `/proc/<pid>/attr/current` | SELinux context of the process |
| `/proc/<pid>/ns/` | Namespace identities (mnt, net, pid, user) |
| `/proc/self/` | The calling process, whatever its pid |
| `/proc/cpuinfo`, `/proc/meminfo` | CPU features (`Features:` line lists `asimd`, `aes`, `pmull`), memory totals |
| `/proc/sys/kernel/yama/ptrace_scope` | 0 = anyone may `ptrace`, 1 = descendants only |
| `/proc/sys/kernel/randomize_va_space` | 0 off, 1 partial, 2 full ASLR |

| Anti-debug check | What it reads |
|---|---|
| `TracerPid` != 0 | `/proc/self/status` |
| Suspicious maps | `/proc/self/maps` grep for `frida`, `gum`, `gadget` |
| Open fds to injected files | `/proc/self/fd/` |
| Thread count anomalies | `/proc/self/task/` |

---

## 15. Command reference — inspecting bytes

| Command | Purpose |
|---|---|
| `xxd file` | Hex + ASCII dump |
| `xxd -l 64 file` | First 64 bytes (ELF/DEX/ZIP magic) |
| `xxd -s 0x1000 -l 256 file` | Dump 256 bytes from offset `0x1000` |
| `xxd -b file` | Binary (bit) dump |
| `xxd -e -g 4 file` | Little-endian grouped by 4 bytes |
| `xxd -r -p hex.txt > out.bin` | Reverse a plain hex dump back to binary |
| `hexdump -C file` | Canonical hex + ASCII |
| `hexdump -n 4 -e '"%08x"' file` | Print first 4 bytes as one hex word |
| `od -A x -t x1z file` | Octal-dump with hex offsets and ASCII |
| `file lib.so` | Identify format, arch, PIE, stripped state |
| `strings -a -n 8 lib.so` | Printable runs of 8+ chars |
| `strings -e l file` | 16-bit little-endian (UTF-16) strings |
| `size -A lib.so` | Section sizes, text/data/bss totals |
| `cmp -l a.bin b.bin` | Byte-level differences |

---

## 16. Command reference — ELF and symbols

| Command | Purpose |
|---|---|
| `readelf -h lib.so` | ELF header |
| `readelf -l lib.so` | Program headers / segments and section-to-segment map |
| `readelf -S lib.so` | Section headers |
| `readelf -d lib.so` | `.dynamic` — `DT_NEEDED`, `DT_SONAME`, `DT_BIND_NOW` |
| `readelf -s lib.so` | Symbol tables |
| `readelf --dyn-syms lib.so` | Dynamic symbols only |
| `readelf -r lib.so` | Relocations |
| `readelf -n lib.so` | Notes, including build-id |
| `readelf -x .rodata lib.so` | Hex dump of a named section |
| `objdump -d lib.so` | Disassemble executable sections |
| `objdump -D -b binary -m aarch64 blob.bin` | Disassemble a raw blob |
| `objdump -d --start-address=0x1234 --stop-address=0x1300 lib.so` | Disassemble a range |
| `objdump -T lib.so` | Dynamic symbol table |
| `objdump -R lib.so` | Dynamic relocations (GOT entries) |
| `objdump -s -j .rodata lib.so` | Contents of a section |
| `nm -C lib.so` | Symbols, C++ names demangled |
| `nm -D lib.so` | Dynamic symbols |
| `nm -u lib.so` | Undefined symbols (imports) |
| `c++filt _ZN3Foo3barEv` | Demangle a single C++ symbol |
| `ldd ./prog` | Shared library dependencies (host only) |
| `readelf -d lib.so \| grep NEEDED` | Dependency list for Android `.so` files |
| `llvm-readelf` / `llvm-objdump` | NDK equivalents in `toolchains/llvm/prebuilt/*/bin/` |

---

## 17. Command reference — runtime tracing

| Command | Purpose |
|---|---|
| `strace ./prog` | Trace all syscalls |
| `strace -f ./prog` | Follow forks and threads |
| `strace -p <pid>` | Attach to a running process |
| `strace -e trace=openat,read,write ./prog` | Filter by syscall |
| `strace -e trace=%memory ./prog` | `mmap`/`mprotect`/`brk` family |
| `strace -e trace=%network ./prog` | Socket family |
| `strace -c ./prog` | Summary counts and time per syscall |
| `strace -tt -T ./prog` | Timestamps and per-call duration |
| `strace -s 256 ./prog` | Show 256 bytes of string arguments |
| `strace -o trace.log -ff ./prog` | One output file per pid |
| `ltrace ./prog` | Trace library (PLT) calls |
| `ltrace -e 'malloc+free' ./prog` | Filter library functions |
| `adb shell strace -p <pid>` | On-device tracing (needs root; `strace` present on `userdebug`) |
| `perf trace` / `simpleperf` | Lower-overhead sampling on Android |

| Command | Purpose |
|---|---|
| `gdb ./prog` | Start debugger |
| `gdb -p <pid>` | Attach |
| `run` / `r` | Start the program |
| `break main` / `b *0x400123` | Breakpoint by symbol / by address |
| `info registers` | All registers |
| `p/x $x0` | Print `X0` in hex |
| `x/16xb $sp` | 16 bytes of the stack in hex |
| `x/8gx $sp` | 8 giant (64-bit) words |
| `x/8i $pc` | Next 8 instructions |
| `bt` | Backtrace |
| `frame 2` / `info frame` | Select / describe a stack frame |
| `stepi` / `nexti` | Single-step one instruction |
| `finish` | Run to end of current function |
| `disassemble` | Disassemble current function |
| `info proc mappings` | Memory map |
| `set $x0 = 1` | Overwrite a register |
| `watch *0x7fff1234` | Data watchpoint |
| `lldb -p <pid>` / `register read` / `memory read` | LLDB equivalents used by the NDK |

---

## 18. Command reference — processes and memory

| Command | Purpose |
|---|---|
| `ps -ef` | All processes |
| `ps -eLf` | All threads (`LWP` column = tid) |
| `ps -o pid,ppid,uid,rss,vsz,stat,comm -p <pid>` | Selected columns |
| `adb shell ps -A` | Android process list |
| `adb shell ps -A -T \| grep <pkg>` | Threads of an app |
| `top -H -p <pid>` | Per-thread CPU |
| `pmap <pid>` | Memory map summary |
| `pmap -x <pid>` | With RSS and dirty columns |
| `cat /proc/<pid>/maps` | Raw map |
| `cat /proc/<pid>/smaps_rollup` | Total PSS/RSS |
| `adb shell dumpsys meminfo <pkg>` | Android-aware memory breakdown |
| `lsof -p <pid>` | Open files |
| `ls -l /proc/<pid>/fd` | Open fds without `lsof` |
| `kill -STOP <pid>` / `kill -CONT <pid>` | Freeze / resume |
| `getconf PAGE_SIZE` | Page size |
| `nproc` / `cat /proc/cpuinfo` | CPU count and features |
| `ulimit -a` | Resource limits including stack size |

| `ps` `STAT` code | State |
|---|---|
| `R` | Running or runnable |
| `S` | Interruptible sleep |
| `D` | Uninterruptible sleep (usually I/O) |
| `T` | Stopped (`SIGSTOP`, or `ptrace`-stopped) |
| `t` | Tracing stop |
| `Z` | Zombie — exited, not yet reaped |
| `+` | Foreground process group |
| `l` | Multi-threaded |

---

## 19. Compilation pipeline

| Stage | Command | Input → Output |
|---|---|---|
| Preprocess | `gcc -E main.c -o main.i` | `.c` → `.i` (macros expanded, headers inlined) |
| Compile | `gcc -S main.i -o main.s` | `.i` → `.s` (assembly text) |
| Assemble | `gcc -c main.s -o main.o` / `as main.s -o main.o` | `.s` → `.o` (ELF relocatable) |
| Link | `ld` / `gcc main.o -o prog` | `.o` + libs → ELF executable or `.so` |
| Load | kernel `execve` + `/system/bin/linker64` | ELF → process image |

| Flag | Effect |
|---|---|
| `-save-temps` | Keep `.i`, `.s`, `.o` from a one-shot build |
| `-O0` / `-O2` / `-Os` / `-Oz` | Optimisation level (`-O0` for readable disassembly) |
| `-g` | DWARF debug info |
| `-fPIC` / `-fPIE -pie` | Position-independent code / executable |
| `-shared` | Produce a `.so` |
| `-static` | Static linking, no `.so` dependencies |
| `-fno-stack-protector` / `-fstack-protector-strong` | Disable / enable stack canaries |
| `-D_FORTIFY_SOURCE=2` | Compile-time and runtime buffer checks |
| `-Wl,-z,relro -Wl,-z,now` | Full RELRO |
| `-Wl,-z,noexecstack` | Non-executable stack |
| `-fsanitize=address` / `hwaddress` | ASan / HWASan instrumentation |
| `-fno-omit-frame-pointer` | Keep `X29` chain for readable backtraces |
| `-Wl,--build-id` | Emit a build-id note |
| `strip --strip-unneeded lib.so` | Remove `.symtab`/`.strtab` |
| `objdump -d` after `-O0` vs `-O2` | Compare to learn what the optimiser did |

| NDK equivalent | Example |
|---|---|
| Compiler driver | `$NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android<API>-clang` |
| Binutils | `llvm-readelf`, `llvm-objdump`, `llvm-nm`, `llvm-strip` in the same `bin/` |
| ABI names | `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86` |

| Model | When code becomes machine code | Android example |
|---|---|---|
| Interpreter | Never — decoded each execution | ART interpreter for cold methods |
| Ahead-of-time (AOT) | Before execution, at build/install time | `dex2oat` producing `.odex`/`.oat` |
| Just-in-time (JIT) | At runtime, for hot methods | ART JIT, writes to an RWX/`mprotect`-flipped region |
| Static compiler | Build time, to native ELF | NDK `clang` producing `.so` |

---

## 20. Quick recall

| Question | Answer |
|---|---|
| Bits in a byte / nibble | 8 / 4 bits, one hex digit |
| Word on AArch64 | `W` = 32 bits, `X` = 64 bits |
| Stack / heap growth | Downward toward lower addresses / upward via `brk`, then anywhere via `mmap` |
| Return address on AArch64 | `X30`/`LR`, spilled to the stack by the prologue |
| Frame record | `[FP, LR]` pair at the frame base, `FP` chained to the caller's record |
| Prologue / epilogue | `stp x29, x30, [sp, #-N]!` + `mov x29, sp` / `ldp x29, x30, [sp], #N` + `ret` |
| Syscall entry and exit | `SVC #0` traps to EL1; `X0` returns the result or `-errno` |
| Process vs thread | Separate address space vs shared address space with a private stack |
| Stack buffer overflow | Write past a local array reaches the saved `FP` and `LR` |
| Use-after-free / double free | Freed chunk used again / freed twice, corrupting allocator metadata |
| Guard page | `PROT_NONE` page that turns an overrun into `SIGSEGV` |
| File descriptors 0, 1, 2 | stdin, stdout, stderr |
| Mutex vs semaphore vs futex | Ownership lock / permit counter / kernel sleep-wake on contention |
