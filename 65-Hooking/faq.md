# 65 — Hooking · FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct; the reasoning
is in [README.md](README.md).

---

### 1. What IS a hook, actually? I have used Frida but I could not explain it.

A hook is a **modification to a running program that makes the CPU go somewhere the program's author
did not intend**, at a place you chose, without changing the file on disk.

That is the whole idea. Everything else is a question of *what you overwrite to achieve it*:

- a pointer inside the runtime's record of a Java method (managed hook);
- the first few instructions of a compiled function (inline hook);
- one entry in a library's table of imported function addresses (PLT/GOT hook);
- the order in which the loader resolves symbols (interposition);
- a function pointer a library handed the JNI runtime (`RegisterNatives`).

When you write `Interceptor.attach(addr, {...})`, Frida overwrites the first instructions at `addr`
with a branch to its own code, copies the instructions it destroyed somewhere safe, and arranges to
jump back. That is it. [Lab 02](labs/lab-02-write-an-inline-hook-by-hand.md) has you do it by hand in
about 250 lines of C, and after that the tool stops being magic.

---

### 2. What is a trampoline, and why do I need one?

To install an inline hook you must **overwrite** the beginning of the target function. Those
instructions are now gone. If you ever want to run the original function — and you usually do, because
you want to see what it *would* have returned — you need them back.

A trampoline is a small piece of memory holding:

1. the instructions you destroyed (fixed up so they still work at their new address), followed by
2. a jump back into the original function, just past your patch.

Call the trampoline and it behaves exactly like calling the original function.

```
your replacement()  ->  trampoline  ->  [displaced instructions]
                                        [jump to target+16]     ->  rest of the original
```

Without a trampoline you can still see arguments and fabricate a return value, but you cannot call
through, so you can never learn what the function would have said.

---

### 3. Why did my hook not fire?

In descending order of likelihood:

1. **The function was inlined away.** The compiler kept the symbol *and* copied its body into the
   caller, so nothing calls it. Check in one command:
   `llvm-objdump -d lib.so | grep "bl.*<yourfunc>"`. No output means no caller in that file.
2. **You attached instead of spawning.** A `static { }` block, an `.init_array` constructor or
   `JNI_OnLoad` all ran before you got there, and they do not run again. Use `frida -U -f <pkg>`.
3. **It is a Java method that ART inlined.** Run
   `adb shell cmd package compile -m verify -f <pkg>`, then force-stop. This throws away the compiled
   code so everything dispatches through the interpreter again.
4. **You hooked the wrong layer.** The Java method you hooked is not the one the app calls; the real
   call is in native code.
5. **The class is in a different `ClassLoader`.** Enumerate them.
6. **It never installed.** Print the bytes before and after — you would be surprised.

The ordered diagnostic is in [cheatsheet.md §11](cheatsheet.md), and
[Lab 03](labs/lab-03-where-hooks-fail.md) makes each failure happen on purpose so you can recognise
it.

---

### 4. My hook fires, prints, returns the value I want — and the app still refuses. What?

You hooked a **producer** whose **consumer** no longer asks it.

The classic case: `isLicensed()` was inlined into `openFeature()`, so `openFeature` contains a copy of
the check and never calls the original. Your hook on `isLicensed` works perfectly — call it directly
and it returns what you forced — and `openFeature` is unmoved.

Measured, from [`examples/hook-that-fails.c`](examples/hook-that-fails.c):

```
lic_is_valid("bad")       = 1   <- the hook demonstrably works
lic_open_feature("bad")   = -1  <- and it changed NOTHING
```

Fix: hook where the decision is **used**, not where it is **computed**. Or hook something the inlined
copy still calls out to — in that example the inlined body still goes through the PLT to `strcmp`, so
a PLT hook reaches it even though an inline hook on the symbol does not.

---

### 5. Can the app see my hook?

Yes, in principle, always. Your hook and the app share one address space with the same credentials.
Anything you can write, it can read.

| Hook type | The obvious tell |
|---|---|
| Inline | The function's first bytes differ from the `.so` on disk; `ldr x16,#8 / br x16` at offset 0 is not something a compiler emits there |
| PLT/GOT | A slot whose value does not fall inside any mapped module — one `dladdr` call away |
| Managed | An `ArtMethod` entry point outside the boot image, the app's `.odex` and the JIT code cache |
| Any | An anonymous `r-x` mapping that is not backed by any file |

But "can be detected" and "is detected" are different, and so are "is detected" and "is stopped". An
in-process check can always be defeated by someone who can already write to that process — the checker
and the checked share a trust domain. That arms race belongs to
[67-BypassingProtections](../67-BypassingProtections/README.md); this chapter owns the mechanism it is
fought with.

---

### 6. Why do I need root?

For most of what people do, yes. For what this chapter teaches, **no**.

Root is needed to **inject code into another process** — which is what `frida-server` does, and it
requires `ptrace` on a process you do not own. That is where the requirement comes from.

It is *not* needed to hook code inside a process you already control. Every measured result in this
chapter — a hand-written inline hook with `adrp` relocation, a PLT/GOT hook, a full CTF solve — was
produced on an **unrooted** Android 13 device with **no `frida-server`**, by a binary that hooks
itself and a library it loaded.

That distinction matters practically: if you can get code into the target process by any other means
(you built the app, you have a debuggable build, you can get a library loaded), you do not need root
at all.

---

### 7. Should I use Frida or write my own hook?

Use Frida. It is better than what you will write, it handles relocation cases yours will not, and it
has a JavaScript REPL.

Write your own **once**, so that when Frida says *"unable to intercept function at 0x…"* you know it
met an instruction it could not relocate, rather than concluding the tool is broken. And write your
own when Frida is not available — an unrooted device, a restricted environment, a target that detects
`frida-server`.

That is why this chapter's examples deliberately do not depend on Frida.
[53-Frida](../53-Frida/README.md) owns the tool; this chapter owns what it is doing underneath.

---

### 8. What is the difference between hooking and patching?

| | Hooking | Patching |
|---|---|---|
| Changes the file on disk | No | Yes |
| Survives a restart | No | Yes |
| Breaks the APK signature | No | Yes |
| Can observe as well as modify | **Yes** | No |
| Needs the process running | Yes | No |
| Needs code execution in the process | Yes | No |

They fail identically in one important respect: if the compiler inlined the function, both a hook and
a patch on that function are useless. [18-ARM §5.4](../18-ARM/README.md) recorded exactly that, and
this chapter's [Lab 03](labs/lab-03-where-hooks-fail.md) restages it for hooks.

---

### 9. Why is `x16` special?

AAPCS64 — the AArch64 calling convention — designates `x16` and `x17` as **IP0** and **IP1**,
intra-procedure-call scratch registers. The standard says a linker may insert a *veneer* (a stub that
extends a branch's reach) at any call site, and that the veneer may destroy IP0 and IP1.

So no correct program may hold a live value in `x16` across a function entry. That is a licence: a
hook installed at a function's first instruction can use `x16` freely, which is why the standard
16-byte patch is `ldr x16, #8 / br x16 / .quad dest`.

**The licence is boundary-specific.** Mid-function, `x16` may be an ordinary live temporary. A hook
placed there must save and restore it.

---

### 10. Why is inline hooking harder on arm64 than on x86?

Mostly **branch range**. AArch64 instructions are all 4 bytes, so their immediates are small: a direct
`b` reaches only ±128 MiB. With a 64-bit address space and ASLR, your replacement is usually further
away than that, so you need a 16-byte absolute jump — which displaces four instructions instead of
one, and every one of them might need relocating.

Then there is `-fPIC`, mandatory for Android shared libraries, which puts an `adrp` in nearly every
prologue. `adrp` is PC-relative, so it cannot be copied — it must be re-encoded.

x86 has the opposite trade: variable-length instructions mean you need a length disassembler just to
know how many bytes you are destroying, but a 5-byte `jmp rel32` reaches ±2 GiB and often fits in one
or two instructions.

---

### 11. What does "relocating an instruction" actually mean? I keep seeing it and nodding.

It means **changing an instruction's bytes so that it still does the same thing from a different
address**.

Some instructions encode a distance from themselves rather than an absolute value. `adrp x8, #1` does
not mean "load 1"; it means "form the address of the page one page after *this instruction*". Copy it
somewhere else and it now points at a different page. No error, no fault — a wrong answer.

Relocating it means: work out where it *pointed*, work out how far that is from its *new* home, and
write a new immediate.

Measured example:

```
[reloc] adrp b0000008 -> f0000008   (target page 0x71f982c000, imm 1 -> 3)
```

The instruction moved 10,004 bytes; the immediate changed from 1 page to 3 pages; the address it
forms is identical.

---

### 12. What happens if I get the relocation wrong?

Usually not a crash where the hook is — which is what makes it dangerous.

If a mis-relocated `adrp` forms the wrong page and the next instruction loads a pointer through it,
you get a garbage pointer. The code then reads or **writes** through it. Best case: `SIGSEGV`
somewhere unrelated. Worst case: a silent write into whatever happens to live at that address, and a
corruption you find hours later in a component you never touched.

That is why this chapter's engine **refuses** every PC-relative form it cannot handle correctly,
rather than copying and hoping. [Lab 02 exercise 7.3](labs/lab-02-write-an-inline-hook-by-hand.md)
has you break it on purpose so you have seen the failure once.

---

### 13. Do I really have to flush the instruction cache?

Yes, and the honest answer is more interesting than the rule.

On AArch64 the data cache and instruction cache are **not coherent**. Your patch is a store — it lands
in the D-cache. The CPU fetches instructions through the I-cache, which is not told. The architecture
requires you to clean the D-cache to the point of unification, invalidate the I-cache, and barrier.
`__builtin___clear_cache(start, end)` emits that.

An experiment was built for this chapter specifically to catch the omission failing: `mprotect` the
page executable-writable once, call the function 2,000,000 times to warm the I-cache, then patch with
no cache maintenance at all and call again.

```
run 1 (no flush):   f("wrong") = 1   (1 = new code ran, 0 = STALE)
run 2 (no flush):   f("wrong") = 1
run 3 (with flush): f("wrong") = 1
```

On that Cortex-A53 it never failed. **That is not permission to skip it.** The architecture *permits*
the CPU to execute the stale line; it does not *require* it to. A different microarchitecture, a
tighter loop, or a second thread already inside the patched range can all change the answer — and it
will change non-deterministically, which is the worst kind of bug to own.

---

### 14. Why did my trampoline end up so far away that the hook failed?

Because an `mmap` hint is **advisory**. You ask politely; the kernel does what it likes.

Measured on the test device: asking for a page 1 MiB after the target returned a page
**11,097,491,692 bytes** away — about 10.3 GiB. `adrp` reaches ±4 GiB, so the displaced `adrp` could
not be re-encoded and the hook correctly refused to install.

The fix is `MAP_FIXED_NOREPLACE`, which means "map exactly here, or fail", and then searching outward
page by page until one succeeds. With the search, the trampoline landed 10,004 bytes from the target.

**Do not use bare `MAP_FIXED`.** It maps at the address you gave and silently unmaps whatever was
there — a library's text, the heap, a thread stack. The process then dies later, elsewhere, for no
visible reason.

---

### 15. When would I use a PLT/GOT hook instead of an inline hook?

Whenever you can, honestly. It is cheaper in every respect: one pointer write, no instruction
analysis, no relocation, no cache flush, and trivially reversible.

Specifically choose it when:

- **Scope is the point.** A PLT hook affects one module's calls only. If the app and its anti-tamper
  SDK both call `open()`, you can hook one and not the other. Measured: after hooking
  `libguard.so`'s `strcmp` slot, the library's call was redirected while the host binary's own
  `strcmp("a","b")` was untouched.
- **The target checksums its own code.** A GOT write changes no instruction, so a `.text` checksum
  sees nothing. That is the entire premise of
  [Lab 04's CTF](labs/lab-04-ctf-the-honest-trampoline.md).
- **The prologue is not relocatable.** Nothing to relocate.

You *cannot* use it when the call is intra-module — a library calling its own function compiles to a
direct branch with no table entry. That case is why inline hooking exists.

---

### 16. Why doesn't `LD_PRELOAD` work on Android?

Because app processes are not `exec`'d. They are **forked from Zygote**, a process that started at
boot, loaded the framework libraries, and resolved its symbols long ago. `LD_PRELOAD` is consulted by
the dynamic linker at `execve`, and for an app there is no `execve` to consult it at.

It does work for a native binary you launch yourself from `adb shell`, because there you control the
environment of the `execve`.

The Android-native replacement is **Zygisk**, which injects into Zygote itself so every subsequently
forked app inherits the injection. See [62-Magisk](../62-Magisk/README.md).

---

### 17. Does full RELRO stop a PLT hook?

No. It costs one `mprotect` call.

Full RELRO (`-Wl,-z,relro,-z,now`) makes the linker resolve everything at load time and then mark the
GOT read-only. That is genuine hardening against **memory-corruption** exploits — a stray write can no
longer land in the GOT and hijack control flow. It is essentially no obstacle to someone who already
executes code in the process, because they can simply call `mprotect` first.

State that precisely when you report it. Over-claiming a control is a fast way to lose a developer's
trust on everything else in the report.

---

### 18. Is "the app can be hooked" a finding?

No. On a device the attacker controls, hooking is a **precondition**, not a vulnerability.

What *is* a finding is what the hook proved:

- "The PIN is `1379-alpha`, hard-coded in `libvault.so`, decoded at runtime with a one-byte XOR."
- "The purchase endpoint accepts a client-asserted `entitled=true` with no server-side check; here is
  the `curl` that reproduces it without any instrumentation."
- "The root check is a single `File.exists`, evaluated once and cached in a static field."

The test is simple: **can you reproduce the impact without your tool?** If yes, you have a finding. If
no, you have a demonstration, and you are not finished.

This is why [Lab 04](labs/lab-04-ctf-the-honest-trampoline.md) grades a bypass as Silver and reserves
Gold for the solution that learns the secret and then throws the hook away.

---

### 19. Can I hook a function that has no symbol?

Yes. Symbols are a convenience, not a requirement.

`dlsym` answers "what did the author publish?", not "what functions exist?". A release library built
with `-fvisibility=hidden` exports only its entry points, and every interesting internal check is
invisible.

The procedure:

1. Find the function statically — disassemble, or use `.symtab` if it survived stripping — and record
   its **file offset**.
2. At runtime, get the module's **load base** (`dl_iterate_phdr`, `/proc/self/maps`, or
   `Process.findModuleByName().base`).
3. The runtime address is `base + offset`.

Everything downstream — relocation, patching, cache flushing — is identical. Only the *finding*
changed. The one thing you must be certain of is that the offset came from **the same build** as the
library on the device.

---

### 20. What is the single most useful habit in this whole chapter?

Print the bytes before and after you patch, and find a **side effect you can count**.

A changed return value proves your replacement ran. It does not prove the original ran, or that you
hooked the function the app actually uses, or that anything downstream noticed. In this chapter's
fixtures the countable side effect is `guard_counter` — after four hooked calls it reads 4, which is
only possible if the original body executed each time through the trampoline.

In a real target it might be a database row, a request on the wire, or a UI transition. Find one.
Almost every confidently wrong conclusion in hooking comes from a tester who checked the return value
and stopped.
