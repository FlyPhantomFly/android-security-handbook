# 19 — Memory — FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct; the long
version is in [README.md](README.md).

---

### 1. What is a page, actually?

The smallest block of memory the hardware can map, protect or account for independently. On almost
every Android device it is **4096 bytes**; since Android 15 some devices use **16384**.

It exists because the table that translates virtual addresses to physical ones needs one entry per
unit. One entry per byte would make the table bigger than the memory it describes. One entry per
4096 bytes makes it manageable.

The consequence you will meet constantly: **every protection decision is per page.** You cannot make
one variable read-only. You can only change the permissions of the whole page it lives in, along
with whatever else shares that page. And `mmap` of one byte gives you 4096 — `examples/mem-landmarks.c
pagesize` prints exactly that.

Ask the device rather than assuming: `getconf PAGESIZE`, or `sysconf(_SC_PAGESIZE)` in C.

---

### 2. Why does `maps` list the same library three or four times?

Because a shared library is loaded **segment by segment**, and the segments need different
permissions.

```
7bd3e7e000-7bd3ebb000 r--p 00000000 fc:04 618   libc.so   <- read-only data, ELF headers
7bd3ebb000-7bd3f4c000 r-xp 0003d000 fc:04 618   libc.so   <- code
7bd3f4c000-7bd3f50000 r--p 000ce000 fc:04 618   libc.so   <- RELRO, locked after relocation
7bd3f50000-7bd3f52000 rw-p 000d1000 fc:04 618   libc.so   <- writable data
```

One file. One inode (`618` in all four rows — that is how you know). One load base. Four mappings,
because the kernel cannot give one mapping four different permission sets.

The linker does this in `ElfReader::LoadSegments` in `bionic/linker/linker_phdr.cpp`: it reserves
the whole span with a single `mmap(PROT_NONE)` and then maps each `PT_LOAD` over part of it with
`MAP_FIXED`.

Analogy: a house is one building with several rooms. Nobody is surprised that the floor plan lists
it more than once.

---

### 3. What do `rw-p` and `r-xp` mean, character by character?

Four characters: **r**ead, **w**rite, e**x**ecute, then the sharing mode.

| Character position | `-` means | letter means |
|---|---|---|
| 1 | cannot read | `r` — can read |
| 2 | cannot write | `w` — can write |
| 3 | cannot execute | `x` — can execute |
| 4 | — | `p` = MAP_PRIVATE (copy-on-write), `s` = MAP_SHARED |

So `rw-p` is data you own and can change but cannot run. `r-xp` is code you can run and read but not
change. `---p` is a **guard page**: mapped, but any access at all faults. `--xp` is **execute-only**,
which is a hardening feature — the CPU can run it and nothing can read it, which stops an attacker
harvesting ROP gadgets from memory.

The fourth character matters more than people think. `rw-s` means another process can change those
bytes while you are using them.

---

### 4. Is ASLR on by default on Android?

Yes — and that answer is misleading enough to be dangerous.

ASLR randomises addresses **when the kernel `exec`s a program**. Android app processes are
**`fork`ed from the Zygote and never `exec`**. The child inherits the parent's page tables, so every
library the Zygote had loaded — `libart.so`, `libc.so`, the boot image, the whole framework — is at
**the same address in every app on the device**, and stays there until the Zygote restarts, in
practice until reboot.

So:

- an address leak from *any* app discloses the framework layout for *every* app on that device;
- an attacker who can run their own app can read their own `/proc/self/maps` and learn where the
  framework is in your app, without touching your app at all.

What *is* still randomised per app: the app's own APK mapping, its `base.odex`, its bundled `.so`
files, and everything mapped after the fork.

The correct sentence for a report is never "ASLR is enabled" or "ASLR is broken". It is: *"the
framework portion of the address space is shared across apps and fixed until reboot; the
app-specific portion is randomised per process."*

This is not a bug in any app. It is the price Android pays for the copy-on-write sharing that makes
app startup fast. See [06-Android-Architecture](../06-Android-Architecture/README.md) for why the
Zygote works that way.

---

### 5. Why can I read another process's `maps` but not its memory?

On desktop Linux, largely true: listing another process's mappings is a read of a `/proc` file
governed by ordinary permissions, whereas reading its *memory* through `/proc/<pid>/mem` requires
`ptrace` capability over it, which `ptrace_scope` often restricts.

**On Android 13, you usually cannot do either.** Verified on a real device:

```
$ adb shell head -3 /proc/$(pidof zygote64)/maps
head: /proc/541/maps: Permission denied
```

SELinux denies the `shell` domain access to an app's `/proc` entries outright. Not the memory — the
*maps file*.

The route that works is to be **inside** the process. An agent injected with Frida runs *as* the
app, so `/proc/self/maps` is its own file and opens without complaint. That is why every
maps-reading technique in this chapter that targets a real app goes through
[`scripts/enumerate-ranges.js`](scripts/enumerate-ranges.js) rather than through `adb shell`.

---

### 6. What is the difference between a heap dump and a memory dump?

| | Heap dump | Memory dump |
|---|---|---|
| Contains | **objects** — classes, fields, references | **bytes** at addresses |
| Covers | the **ART (Java)** heap only | whatever regions you dumped, including native |
| Format | HPROF | raw, or an ELF core file |
| Produced by | `am dumpheap`, Android Studio Profiler | Frida, `/proc/<pid>/mem`, a tombstone |
| Read with | Android Studio, Eclipse MAT | a hex editor, `strings`, a script |
| Answers | "which object holds this string, and what keeps it alive?" | "what bytes are at this address?" |

They are not interchangeable and they produce findings with different remediations. "We found the
token in a heap dump" has an obvious fix direction (stop holding it in a `String`); "we found it in
native memory at `0x73…`" does not.

**Never write "we dumped the heap" without saying which heap.**

---

### 7. Why does `malloc` return `0xb400007cbeeee2e0` when the region starts at `0x7cbeeee000`?

The top byte, `0xb4`, is a **tag**, not part of the address.

Arm's Top-Byte-Ignore feature means the hardware ignores the top byte of a 64-bit pointer when
dereferencing it, so software may use it for metadata. Since Android 11, 64-bit processes whose apps
target API 30 or higher get a tag in every heap pointer. The constant is `POINTER_TAG` in
`bionic/libc/bionic/malloc_tagged_pointers.h`, and its value is `0xB4`.

`/proc/<pid>/maps` prints **untagged** addresses. So a comparison between a `malloc` return value and
a maps range matches nothing until you mask it:

```c
uintptr_t clean = (uintptr_t)p & (uintptr_t)0x00ffffffffffffffULL;
```

Under HWASan or MTE the tag is **random per allocation** rather than a constant, which is why two
pointers to the same memory can compare unequal.

Note the `ULL`. Writing `UL` compiles fine on arm64 and silently truncates on armeabi-v7a, where
`unsigned long` is 32 bits — a real bug that building the chapter's example for both ABIs caught.

---

### 8. Which allocator is Android using — Scudo or jemalloc?

The rule: **Scudo for all native code since Android 11, except on low-memory devices, where jemalloc
is still used.** Scudo was introduced in Android 10 but was not yet the default.

The rule is not enough, because the exception is real and because OEMs vary. **Read it from
evidence:**

```bash
adb shell cat /proc/self/maps | grep -o '\[anon:[^]]*\]' | sort -u
```

`[anon:scudo:primary]` means Scudo. `[anon:libc_malloc]` means the older path.
`[anon:SizeClassAllocator: region data]` means a sanitiser has replaced the allocator entirely.
`python3 scripts/maps-analyse.py maps.txt` does this lookup for you and prints the evidence
alongside the conclusion.

---

### 9. Does `free()` erase the data?

**No.** Measured on a stock Android 13 arm64 device:

```
Contents, before and after:
  small[0] now   41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
  after free     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
```

Scudo has a `ZeroContents` option and Android does not enable it. The old bytes stay in the page
until something else claims it and overwrites it — which may be never.

This is the mechanism behind every "we found the session token in a heap dump" finding. The fix is
to overwrite the secret yourself before freeing, with something the optimiser is not allowed to
delete. A plain `memset` before `free` is legal C that the compiler *may remove* as a dead store,
because the memory is dead. Use a `volatile` write loop — and confirm that `explicit_bzero()`, which
every guide recommends, is **absent from the NDK r25c sysroot** and fails at link time.

---

### 10. Every app has an `rwxp` page. Is that a compromise?

No. ART's JIT compiler writes machine code and then runs it, so it needs memory that is both
writable and executable. `[anon:dalvik-jit-code-cache]` is `rwxp` in every Android app that has ever
shipped.

The questions that separate the boring case from the interesting one:

| Question | Boring answer | Interesting answer |
|---|---|---|
| Is it named? | `[anon:dalvik-jit-code-cache]` | unnamed |
| How big? | megabytes, growing | 16 KiB |
| What is at the start? | ARM64 code | an ELF header — a library loaded from memory |
| Who created it? | ART | something you have not identified |
| Is it yours? | — | **your own Frida agent maps RWX regions too** |

That last row catches people out. `enumerate-ranges.js` labels Frida's own footprint deliberately,
because a report that quietly filters out the observer is a report that has started lying.

---

### 11. My HWASan build runs and reports nothing. Does that mean there are no bugs?

Almost certainly not. Three explanations to rule out first:

1. **The instrumentation is not there.** Only code compiled with `-fsanitize=hwaddress` is
   instrumented. A prebuilt `.so` you did not rebuild is invisible to it. **Test:** run the known
   buggy fixture (`heap-bugs-hwasan uaf`) in the same session and confirm it fires.
2. **The runtime did not load.** The instrumented binary needs
   `libclang_rt.hwasan-aarch64-android.so` alongside it. **Test:** run `maps-analyse.py` on the
   process's maps — if the allocator still fingerprints as Scudo, HWASan is not running.
3. **The buggy path never executed.** A sanitiser only sees code that runs. Drive the specific
   feature, do not just launch the app.

And the control that makes any positive result trustworthy: run the *fixed* source under the same
instrumentation and confirm it is silent. A checker that is quiet on both builds is not switched on.

---

### 12. HWASan or MTE — what is the actual difference?

They implement the same idea: give each 16-byte granule a tag, give each pointer a tag, check they
match on every access.

The difference is **who checks**.

| | HWASan | MTE |
|---|---|---|
| Who checks | the **compiler** inserts a check before every load and store | the **CPU** checks, in hardware |
| Rebuild needed | **yes** | **no** for heap tagging |
| Hardware | any AArch64 | Armv8.5-A and later |
| Tag size | a full byte — 256 values | 4 bits — 16 values, so ~1 in 16 mismatches collide |
| Report | access + **allocation stack** + **free stack** | a `SIGSEGV` with `SEGV_MTESERR` and registers |
| Overhead | ~2× memory, high CPU | low in `async` mode |
| Shippable | no | **yes**, in `async` |

In practice: **HWASan in CI**, because the three stack traces are worth the overhead when nothing is
waiting; **MTE `async` in production** where the hardware allows, because it catches bugs on real
users' devices.

---

### 13. GWP-ASan found nothing. Is the app clean?

No, and this is worth being blunt about. GWP-ASan samples roughly **1%** of allocations. A bug on a
path you trigger once will almost certainly be missed.

It is a *fleet* tool. Across a million installs, 1% sampling finds what matters because the bug
happens constantly somewhere. Across your two-week engagement, it is free, occasionally lucky, and
**a negative result from it is not evidence of anything**.

Say that in the report. "We ran with GWP-ASan and found no issues" without the coverage caveat is a
statement the client will read as a clean bill of health.

---

### 14. Why did my double free crash but my 64-byte overflow did not?

Because Scudo validates a chunk's header **when that chunk is freed**, and nothing else.

- **Double free:** the second `free()` reads a header that is in the wrong state. Detected
  immediately — `Scudo ERROR: invalid chunk state when deallocating address 0x…`
- **Invalid free:** the header where the allocator looks fails its checksum. Detected immediately —
  `Scudo ERROR: corrupted chunk header at address 0x…`
- **Overflow:** you damaged the *next* chunk's header. That is only noticed when *that* chunk is
  freed, which may never happen. So the process carries on and exits 0.
- **Use-after-free:** nothing looks at anything. Completely silent.

Measured, all four, on a real device. The corollary for a developer conversation: "exit code 0" means
nothing was *detected*, not that nothing was *wrong*.

---

### 15. What is `[heap]`, and why is nothing in it?

`[heap]` is the classic Unix `brk` region. bionic barely uses it — it allocates by `mmap` instead.

The real native heap is a set of **named anonymous** mappings: `[anon:scudo:primary]` and
`[anon:scudo:secondary]`. If you go looking for the heap under the label `[heap]` you will find a
small, mostly empty region and conclude something is wrong.

And the Java heap is somewhere else again: `[anon:dalvik-main space (region space)]`.

---

### 16. `Process.enumerateRanges()` shows fewer ranges than `maps` has lines. Is Frida hiding something?

No. Frida **coalesces** adjacent ranges that share a protection into one object, so a group of
consecutive identical-permission mappings becomes one entry beginning at the first.

More importantly, Frida's view loses three things that `maps` has:

| Lost | Why it matters |
|---|---|
| the `p`/`s` sharing bit | Frida's `protection` string is three characters; a shared writable mapping looks private |
| device and inode | you cannot tell whether two mappings of the same path are the same file |
| the ` (deleted)` marker | **a mapping whose file was unlinked looks identical to one whose file still exists** |

That third one is the significant omission for anyone hunting dropped payloads, and it is why
`enumerate-ranges.js` reads `/proc/self/maps` directly and diffs the two.

---

### 17. How do I turn a static address from Ghidra into a runtime address?

```
runtime address = load base + static address
```

The load base is the **lowest mapping of that file whose file offset is `00000000`**. Not its
lowest mapping.

The difference bites for a library mapped straight out of an APK (`android:extractNativeLibs="false"`),
where the `.so` starts part way into the ZIP and no mapping has offset zero. Using the lowest mapping
there gives a base that is wrong by however far in the library sits — and the error is **silent**:
every computed address still lands inside the library, in a plausible-looking place.

`maps-analyse.py` prints a `?` after the base when it cannot find a zero-offset mapping, precisely so
you notice. Frida's `Module.findBaseAddress` uses the correct definition.

And the mistake behind the mistake: a `malloc` return value is not inside any module, so subtracting
a module base from it produces a meaningless number no matter how carefully you untag it.

---

### 18. Is finding a session token in memory a vulnerability?

Usually **no**, and reporting it as one costs you credibility.

A process that is *using* a token has to hold it somewhere. An attacker who can read that process's
memory has already won by other means — they have root, or debugging access, or code execution.

It becomes a finding when:

- the token is **still there long after** the code claims to have cleared it (use the before/after
  test in `mem-search.js`'s `scrubTest`);
- it **outlives the session**, in a background process or a cache;
- it can be reached **without code execution** — a heap dump collected by a crash reporter and
  uploaded off the device is the classic case;
- the threat model **explicitly includes** a local attacker with debugging access.

Otherwise: report it as informational, say why, and move on.

---

### 19. What does "reachable" mean, and why do you keep saying it?

Because it is what decides the severity, and it is the thing most reports skip.

A memory-safety defect is a **finding** when you can name the path from attacker-influenced input to
the bad access. It is an **observation** when you cannot. The chain has six links:

1. attacker-influenced data reaches the function;
2. the bad access happens on that path;
3. the corrupted memory is adjacent to something useful;
4. the attacker controls what goes into that adjacent memory;
5. the corrupted value is subsequently read or called;
6. the mitigations do not stop the final step.

State which links you confirmed and which you did not. "Links 1–5 confirmed, 6 not attempted" is
honest, checkable, and more persuasive than a confident "critical" with nothing behind it.

**And a bug that cannot be reached is a low-severity finding. Say so plainly.** Padding a report with
unreachable `strcpy` calls trains the client to ignore you — which means they also ignore the one
that mattered.

---

### 20. Why does my code break on a Pixel with 16 KB pages?

Because something hard-codes 4096.

Two failure modes:

1. **The library will not load at all.** A `.so` whose `PT_LOAD` segments are aligned to 4 KiB cannot
   be mapped on a 16 KiB-page device. Fix with `-Wl,-z,max-page-size=16384` and
   `-Wl,-z,common-page-size=16384` (NDK r27 and lower), and check with `llvm-readelf -l` that no
   `LOAD` alignment is below `2**14`.
2. **It loads and misbehaves.** Code that rounds an `mmap` length or computes a page base for
   `mprotect` using a literal `4096` computes the wrong number and either fails the syscall or
   protects the wrong memory. **The symptoms look exactly like memory corruption**, which is why this
   is worth checking before you spend a day chasing a heap bug that is not there.

Use `sysconf(_SC_PAGESIZE)` or `getpagesize()`. On NDK r27 and higher, `PAGE_SIZE` is deliberately
undefined in 16 KB mode so the assumption cannot compile.

Google Play requires 16 KB support for apps targeting Android 15 and higher, with updates rejected
from **1 February 2027**.

---

### 21. Do I need root for any of this?

| Task | Root needed? |
|---|---|
| Read your own shell process's `maps` | no |
| Build and run the fixtures in `/data/local/tmp` | no |
| Run `maps-analyse.py` on a capture | no |
| Read a *target app's* `maps` via `adb shell` | yes — SELinux denies `shell` |
| Read a target app's `maps` via an injected agent | no root, but you need to attach |
| Attach Frida to a release app | yes, or an emulator, or a debuggable build |
| `am dumpheap` on a release app | yes, or a debuggable build |
| Read `/proc/<pid>/mem` of another process | yes |
| Enable MTE via `am compat` | no |
| Enable GWP-ASan via the manifest | no — but you need to rebuild the APK |
| `setprop libc.debug.malloc.options` | yes, generally |

The honest summary: everything in Labs 01 and 02 works on an unrooted device with the shipped
fixtures. Everything that targets a *real third-party app* needs either root, an emulator, or a
debuggable build — which is [53-Frida](../53-Frida/README.md)'s problem, not this chapter's.

---

### 22. Where does this chapter stop and another begin?

| You want to know | Chapter |
|---|---|
| What is in the `.so` file; is it built with RELRO and canaries | [15-Native-Code](../15-Native-Code/README.md) |
| Where it is at run time; page protections; where `malloc` put this | **19 — here** |
| How Java calls into it; what `JNIEnv` is | [16-JNI](../16-JNI/README.md) |
| Which third-party library it is and whether that version is vulnerable | [17-Libraries](../17-Libraries/README.md) |
| What is on the **Java** heap; `ArtMethod`; GC | [13-ART](../13-ART/README.md) |
| Why every app is a fork of the Zygote | [06-Android-Architecture](../06-Android-Architecture/README.md) |
| What stops app A reading app B's files | [21-App-Sandbox](../21-App-Sandbox/README.md) |
| What this decompiled function does | [57-Ghidra](../57-Ghidra/README.md) |
| How to hook it | [53-Frida](../53-Frida/README.md) |
| What this AArch64 instruction means | 18-ARM |

The quick test: if the answer comes out of `readelf`, it is chapter 15. If it comes out of
`/proc/<pid>/maps` or a `malloc` return value, it is here. If it comes out of a heap dump full of
Java objects, it is chapter 13.
