# Lab 01 — The five hook types, on one target

> **Objective.** Take a single, observable behaviour and intercept it five different ways, so that
> "hooking" stops being one word and becomes five distinct mechanisms with five distinct
> prerequisites, blast radii and failure modes. By the end you will be able to look at a target and
> say *which* hook you need before you write a line of code.

**Difficulty:** beginner → intermediate
**Time:** 90 minutes
**Prerequisites:** [15-Native-Code](../../15-Native-Code/README.md),
[17-Libraries](../../17-Libraries/README.md), [18-ARM §3.3](../../18-ARM/README.md)
**Device used to verify this lab:** `i9000S`, Android 13 / API 33, **unrooted, no frida-server**.
Everything in sections 1–5 runs without root. Section 6 requires root and is marked as unverified
here.

---

## 0. What you are about to learn, in one sentence

A hook is a **redirection of control flow that the original program did not author**, and the five
ways to install one differ only in *what you overwrite*: an ART method's entry pointer, a function's
first instructions, an import table entry, a symbol resolution order, or a JNI method table.

---

## 1. Setup

### 1.1 Build the fixtures

```bash
# host
cd 65-Hooking/examples
export ANDROID_NDK=$HOME/Android/Sdk/ndk/25.2.9519653
./build-hook-fixtures.sh
```

This builds, into a scratch directory outside the repository:

| Artefact | What it is |
|---|---|
| `libguard.so` | The target. Exports `guard_check`, `guard_level`, `guard_name`, `guard_counter` |
| `libinline.so` | A target whose check function is inlined away |
| `trampoline-hook` | Hand-written inline hook (Lab 02's subject) |
| `plt-got-hook` | PLT/GOT slot swap (this lab, §4) |
| `hook-that-fails` | A correct hook on a function nobody calls (Lab 03's subject) |

> **⚠️ Warning.** The build script writes to `$OUT`, which defaults to a temporary directory. It
> never writes a `.so` or an executable into this repository. Binaries are on the artefact blocklist.
> If you see one appear under `65-Hooking/`, delete it.

### 1.2 Confirm you can execute on the device

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
```

Record what you get. Two devices are in rotation for this repository and they differ in
**capability**, not only version — one is rooted with `frida-server`, one is neither. A lab step that
"does not work" is very often a lab step running on the wrong phone.

```bash
# host
adb push $OUT/libguard.so /data/local/tmp/
adb push $OUT/plt-got-hook /data/local/tmp/
adb shell chmod 755 /data/local/tmp/plt-got-hook
adb shell /system/bin/linker64 /data/local/tmp/plt-got-hook
```

> **🔬 Under the Hood.** Why `/system/bin/linker64` and not just `/data/local/tmp/plt-got-hook`?
> Because on many vendor builds a direct `execve` of a file in `/data/local/tmp` is refused — the
> shell reports `No such device or address` and exits 126, which is a maximally unhelpful message for
> "this filesystem will not let me execute that". Handing the binary to the dynamic linker works,
> because the linker itself lives in `/system/bin`, which is executable, and loading a program is
> precisely its job. This is not a privilege bypass; you are still the `shell` user with the same
> SELinux context. Documented in [18-ARM §7.7](../../18-ARM/README.md).

---

## 2. Hook type 1 — managed layer (ART entry point)

**What you overwrite:** `ArtMethod::entry_point_from_quick_compiled_code_`, a pointer field inside
the runtime's own bookkeeping structure for a Java method.

**Prerequisite:** a Java VM in the process, and the ability to write to the runtime's memory —
in practice, root plus an injection mechanism (`frida-server`, or Zygisk).

This chapter **does not restage the mechanism**; it belongs to
[13-ART §3.15–3.17](../../13-ART/README.md), which derives the structure, shows how to locate the
field without hard-coding an offset, and ships
[`13-ART/scripts/artmethod-inspect.js`](../../13-ART/scripts/artmethod-inspect.js).

What you need to carry forward into this chapter is the **shape** of the mechanism, because it is
the odd one out:

| | Managed hook | Every other hook in this lab |
|---|---|---|
| What changes | A field in a runtime data structure | Instructions, or a pointer in the target's own tables |
| Granularity | One method, exactly | One symbol, one import, or one process |
| Needs instruction analysis | No | Yes, for inline hooks |
| Survives recompilation | No — a new entry point is written by the JIT | Yes |
| Detectable by | Reading the entry point back | Reading the code, or the GOT |

### 2.1 Exercise

You cannot run this on an unrooted device, and pretending otherwise would be dishonest. Instead,
answer from [13-ART](../../13-ART/README.md):

1. If a method has been AOT-compiled and its caller has also been AOT-compiled with the callee
   **inlined**, does replacing the callee's entry point change the caller's behaviour? Why not?
2. What single `adb` command is the highest-value response to "my managed hook installed but never
   fired", and what does it actually do to the target?
3. Which field would you read to distinguish *interpreted*, *AOT* and *JIT* state for a method?

<details>
<summary>Answers</summary>

1. **No.** The inlined copy is a duplicate of the callee's body, emitted inside the caller's compiled
   code. It does not dispatch through `ArtMethod` at all, so there is no entry point to replace on
   that path. 13-ART's four-cause table names this as the first cause of "hook installed, never
   fires".
2. `adb shell cmd package compile -m verify -f <pkg>`, followed by a force-stop. It recompiles the
   package at the `verify` filter, which produces **no compiled code**, so every method executes in
   the interpreter and every dispatch goes through the entry point again.
3. `entry_point_from_quick_compiled_code_`, compared against the runtime's known trampolines. That is
   exactly what `artmethod-inspect.js` classifies, deriving the offset at runtime rather than
   hard-coding it — because ART is a Mainline module and the struct layout differs between devices
   reporting the same Android release.

</details>

---

## 3. Hook type 2 — inline / trampoline

**What you overwrite:** the first N bytes of the function's compiled code, replacing them with a
branch to your replacement.

**Prerequisite:** the ability to make a code page writable, and enough understanding of the
instruction encoding to relocate whatever you displaced.

This is Lab 02's whole subject and the chapter's spine. For now, just run it and read the output:

```bash
# host
adb push $OUT/trampoline-hook /data/local/tmp/
adb shell chmod 755 /data/local/tmp/trampoline-hook
adb shell /system/bin/linker64 /data/local/tmp/trampoline-hook
```

Measured on the `i9000S`, API 33:

```
guard_check @ 0x71f982b714

== BEFORE ==
  guard_check("wrong")        = 0
  guard_check("s3cr3t-token")  = 1
  original prologue:
    0x71f982b714:  a9bf7bfd        stp  x29, x30, [sp, #-16]!
    0x71f982b718:  910003fd        mov  x29, sp
    0x71f982b71c:  b0000008        adrp x8, ...          <- PC-RELATIVE
    0x71f982b720:  f944ad08        ldr  x8, [x8, #2392]

trampoline page @ 0x71f9829000  (-10004 bytes from target)

== RELOCATING the 4 displaced instructions ==
    [copy ] a9bf7bfd  (position independent)
    [copy ] 910003fd  (position independent)
    [reloc] adrp b0000008 -> f0000008   (target page 0x71f982c000, imm 1 -> 3)
    [copy ] f944ad08  (position independent)

== AFTER ==
  patched prologue:
    0x71f982b714:  58000050        ldr x16, #8
    0x71f982b718:  d61f0200        br  x16
    0x71f982b71c:  8be11520        (low half of the replacement's address)
    0x71f982b720:  00000074        (high half)
  guard_check("wrong")        = 1
  guard_check("s3cr3t-token")  = 1

guard_counter = 4
```

Three things to notice now, and understand fully in Lab 02:

1. **Sixteen bytes were overwritten**, not four, because an absolute jump needs to carry a full
   64-bit address and there is nowhere else to put it.
2. **One of the four displaced instructions changed value** when it moved. `b0000008` became
   `f0000008`. It is the same `adrp`, re-encoded so it still forms the same page from a different
   address.
3. **`guard_counter` reads 4 after four calls.** The original body ran every time. The hook
   intercepted the *result*; it did not replace the *function*.

---

## 4. Hook type 3 — PLT / GOT

**What you overwrite:** one pointer in the target library's import table.

**Prerequisite:** the symbol must actually be **imported** by that library — that is, the call must
cross a module boundary and go through the PLT.

```bash
# host
adb shell /system/bin/linker64 /data/local/tmp/plt-got-hook
```

Measured on the `i9000S`, API 33:

```
== BEFORE ==
  guard_check("wrong") = 0

load base = 0x7cd6a76000
DT_JMPREL entries = 3
  [0] type=1026 sym=__cxa_finalize   slot=0x7cd6a78978
  [1] type=1026 sym=__cxa_atexit     slot=0x7cd6a78980
  [2] type=1026 sym=strcmp           slot=0x7cd6a78988
      -> slot currently 0x7f67aa2280 ; overwriting with 0x7f6b731164

== AFTER (GOT slot swapped, not one instruction changed) ==
    [plt] strcmp("wrong", "s3cr3t-token") intercepted -> forcing 0 (equal)
  guard_check("wrong")  = 1   <- the library's call was redirected
  host strcmp("a","b") = -1  <- this process's OWN call was not
```

### 4.1 The two lines that matter

`guard_check("wrong")` went from 0 to 1. `strcmp("a","b")` from the host binary did **not** change.
Same process, same libc, same function — two different answers, because the hook did not touch
`strcmp`. It touched *libguard.so's idea of where `strcmp` lives*.

> **🧠 Mental Model.** A PLT/GOT hook is not a hook on a function. It is a hook on a **relationship**:
> "this module, calling that symbol". Every loaded library keeps its own table, so hooking one leaves
> the rest alone. That is a feature when an app and its anti-tamper SDK both call `open()` and you
> only want to see the app's calls. It is a trap when the call you care about comes from a library
> you forgot to patch.

### 4.2 Relocation type 1026

`1026` is `0x402`, which is `R_AARCH64_JUMP_SLOT`. If you see `1025` (`R_AARCH64_GLOB_DAT`) instead,
the reference resolved through `.got` rather than `.got.plt`, and the entries live under `DT_RELA`
rather than `DT_JMPREL`. The technique is identical; only the table you walk changes.

### 4.3 Exercise — find the hookable imports of any library

```bash
# host
cd 65-Hooking/scripts
./hook-surface.sh $OUT/libguard.so
```

Measured output, abridged:

```
== 1. PLT/GOT HOOKABLE IMPORTS (JUMP_SLOT relocations) ==
   __cxa_atexit
   __cxa_finalize
   strcmp
   (3 JUMP_SLOT relocations total)

== 2. RELRO / BIND_NOW ==
   FULL RELRO. The GOT is made read-only after relocation.
   A PLT hook still works; you must mprotect the slot's page to
   PROT_READ|PROT_WRITE first, then restore it.
```

Note the second block carefully. **Full RELRO does not prevent a PLT hook.** It makes the table
read-only after the linker finishes, which stops an *accidental* write and costs an attacker exactly
one `mprotect` call. Security controls that raise the cost by one syscall are worth knowing about
and worth not over-claiming.

Now run it against a real system library and see how different the surface looks:

```bash
# host
adb pull /system/lib64/libsqlite.so /tmp/
./hook-surface.sh /tmp/libsqlite.so | head -40
```

**Question:** `libsqlite.so` imports `open`, `read`, `write` and `pread64`. If you swap its GOT slot
for `open`, does that intercept an app's `SQLiteDatabase.openDatabase(...)` call? Under what
circumstances would it not?

<details>
<summary>Answer</summary>

Usually yes, *if* the app's database access really descends through this copy of `libsqlite.so`. It
would not if:

- the app bundles its own SQLite (very common — Room, Realm, SQLCipher and several analytics SDKs
  ship a private build), in which case there is a *different* library with a *different* GOT;
- the call was made before you installed the hook (see Lab 03 on the timing problem);
- the platform library was loaded into a different process than the one you patched.

The general lesson: a PLT hook's scope is a module, and "the module I found" is not automatically
"the module that runs".

</details>

---

## 5. Hook type 4 — symbol interposition (`LD_PRELOAD`-style)

**What you overwrite:** nothing. You change the **order in which symbols are resolved**, so the
dynamic linker binds calls to your definition instead of libc's, before the program starts.

**Prerequisite:** control of the process's environment at launch. On Linux that is `LD_PRELOAD`.
On Android it is nearly always unavailable for app processes, and this is the single most important
practical fact about this hook type.

### 5.1 Why `LD_PRELOAD` mostly does not work on Android

Android apps are not `exec`'d. They are **forked from Zygote**, which has already started, already
loaded its libraries and already resolved its symbols. There is no `execve` at which the linker
consults `LD_PRELOAD` for the app. Even where a process *is* exec'd, bionic ignores `LD_PRELOAD` for
setuid binaries and the app sandbox prevents you from setting the environment of another app's
process at all.

Where it *does* work:

| Scenario | Works? | Why |
|---|---|---|
| An app process forked from Zygote | **No** | No `execve`; symbols already bound in the Zygote parent |
| A native binary you launch from `adb shell` | **Yes** | You control the environment of the `execve` |
| A native helper process the app spawns | Sometimes | Only if you control how it is launched |
| Anything with `android:isolatedProcess` | No | Separate, more restricted sandbox |

### 5.2 Prove it, in the one place it works

```bash
# host — build a preload library and a victim
cat > /tmp/preload.c <<'EOF'
#include <stdio.h>
#include <string.h>
int strcmp(const char *a, const char *b) {
    printf("[preload] strcmp(\"%s\", \"%s\")\n", a, b);
    return 0;                      /* everything is equal now */
}
EOF
$NDK/aarch64-linux-android21-clang -shared -fPIC -o /tmp/libpreload.so /tmp/preload.c

adb push /tmp/libpreload.so /data/local/tmp/
adb push $OUT/libguard.so   /data/local/tmp/
```

Then run any binary that calls `strcmp` with the preload set:

```bash
# host
adb shell "LD_PRELOAD=/data/local/tmp/libpreload.so /system/bin/linker64 /data/local/tmp/plt-got-hook"
```

**Question before you run it:** the `plt-got-hook` binary already swaps the GOT slot itself. If
`LD_PRELOAD` binds `strcmp` to your preload library, what will the GOT slot contain *before* the
program overwrites it, and what does that tell you about the ordering of the two mechanisms?

<details>
<summary>Answer</summary>

The slot will already point at `libpreload.so`'s `strcmp`, because the linker resolved it that way at
load time — **interposition happens first, during relocation; a GOT patch happens later, at
runtime.** The program's own patch then replaces the preloaded pointer.

This is the general relationship: symbol interposition decides what the table is *initialised* to; a
PLT/GOT hook decides what it *becomes*. They act on the same pointer at different times, and the last
writer wins.

</details>

### 5.3 The Android-native equivalent

The mechanism that fills the `LD_PRELOAD` gap on Android is **Zygisk**, which injects into Zygote
itself so that every forked app inherits the injected code. That is `62-Magisk`'s subject; see
[62-Magisk](../../62-Magisk/README.md), which documents `hookJniNativeMethods()` — the API name is a
direct pointer to hook type 5, below.

---

## 6. Hook type 5 — `RegisterNatives` table rewriting

**What you overwrite:** the `fnPtr` field in a `JNINativeMethod` entry that the library handed to the
runtime, or the runtime's stored copy of it.

**Prerequisite:** the library must register its natives **dynamically**. If it uses static
registration (exported `Java_com_example_Foo_bar` symbols), there is no table — the runtime resolves
by name, and you hook the symbol like any other native function.

The mechanism belongs to [16-JNI §3.8](../../16-JNI/README.md), which derives the structure, shows the
registration call, and ships
[`16-JNI/scripts/dump-registernatives.js`](../../16-JNI/scripts/dump-registernatives.js). What
belongs *here* is why it is a distinct hook type at all:

- The Java-method-to-C-function mapping **exists only in memory, only after `JNI_OnLoad` has run**.
  Static analysis of the `.so` cannot tell you which C function backs `Foo.bar` — the strings are
  passed as arguments, sometimes constructed at runtime.
- Because the mapping is data, rewriting it changes **every future dispatch** with **no instruction
  modified**. A code checksum sees nothing.
- Because it happens in `JNI_OnLoad`, it is a **timing** problem: hook `RegisterNatives` itself, or
  arrive too late and find only the result.

### 6.1 Detect the surface statically

```bash
# host
cd 65-Hooking/scripts
./hook-surface.sh /path/to/libnative.so --jni
```

The script reports both halves:

- `Java_*` exports — statically registered, hookable by symbol name, and the mangled name decodes
  back to a Java class and method with
  [`16-JNI/scripts/jni_mangle.py`](../../16-JNI/scripts/jni_mangle.py).
- `JNI_OnLoad` present — dynamic registration is possible, and everything above applies.

> **🔍 Pentester's Note.** A library with `JNI_OnLoad` and **no** `Java_*` exports is telling you
> something: every native method it provides is registered dynamically, deliberately, and you will
> not learn the mapping from the file. That is not proof of hostility — it is also faster and lets
> the developer use short C function names — but it does mean your analysis has to be dynamic.

### 6.2 Honest limitation for this lab

Running a `RegisterNatives` interception requires injecting into an app process, which requires root
on this device. **It was not executed while writing this chapter**, because the attached device
(`i9000S`, API 33) is unrooted and has no `frida-server`. The static detection in §6.1 *was* run. Any
step in this repository that was measured says so and shows numbers; this one says the opposite.

---

## 7. Putting it together — choose the hook before you write it

For each scenario, name the hook type you would reach for **first**, and one reason it might fail.

| # | Scenario |
|---|---|
| 1 | A Kotlin method `isDeviceRooted()` returns `true`; you want `false`. Rooted device, Frida available |
| 2 | A native library calls `access("/system/bin/su", F_OK)`; you want it to fail |
| 3 | You want to log every file the whole process opens, including the runtime's own opens |
| 4 | A native method `Java_com_x_Crypto_sign` exists in `.dynsym`; you want its arguments |
| 5 | `libfoo.so` exports nothing useful, has `JNI_OnLoad`, and its Java class declares five `native` methods |
| 6 | You want to intercept a call that a library makes to a function **inside itself** |

<details>
<summary>Answers</summary>

1. **Managed (ART entry point).** Fails if the method was inlined by the AOT compiler, or the class
   is loaded by a non-default `ClassLoader`. Fix: `cmd package compile -m verify -f`.
2. **PLT/GOT** on that library's `access` import. One pointer, reversible, invisible to a code
   checksum. Fails if the library resolves `access` itself with `dlsym` and calls through a stored
   pointer that never goes through the PLT — then you need an inline hook on libc's `access`.
3. **Inline hook on libc's exported `access`/`openat`.** Process-wide is exactly what you asked for.
   Fails, or rather overwhelms you, because the runtime opens hundreds of files; you will need
   filtering, and you have made every module's calls your problem.
4. **Inline hook on the exported symbol.** Static registration means the symbol is the entry point.
   Fails if the prologue cannot be relocated — run `hookability.py` first.
5. **`RegisterNatives` table rewriting**, and you must hook `RegisterNatives` itself to catch the
   registration as it happens. Fails if you attach after `JNI_OnLoad` has already run — the timing
   problem, Lab 03 §4.
6. **Inline hook only.** An intra-module call is a direct `bl` with a fixed displacement; there is no
   table entry to swap and no symbol to interpose. This is the case that justifies inline hooking's
   existence.

</details>

---

## 8. Success criteria

You have finished this lab when you can, without looking anything up:

- [ ] Name all five hook types and state, for each, **what byte or field is overwritten**.
- [ ] Explain why a PLT/GOT hook changed `guard_check`'s behaviour but not the host binary's
      `strcmp` call, in terms of *which table* was modified.
- [ ] State why `LD_PRELOAD` does not work for Android app processes, in one sentence about Zygote.
- [ ] Explain why `RegisterNatives` hooking is a *timing* problem and inline hooking usually is not.
- [ ] Given a `.so`, run `hook-surface.sh` and read off which functions are PLT-hookable and which
      are inline-hookable.
- [ ] Say what "Full RELRO" costs an attacker, precisely, without over-claiming.

---

## 9. Where to go next

| If you want to | Go to |
|---|---|
| Build an inline hook yourself, by hand, including relocation | [Lab 02](lab-02-write-an-inline-hook-by-hand.md) |
| Understand why a correct hook can change nothing | [Lab 03](lab-03-where-hooks-fail.md) |
| Defeat three layered defences with the right hook type | [Lab 04 (CTF)](lab-04-ctf-the-honest-trampoline.md) |
| Learn the managed layer properly | [13-ART](../../13-ART/README.md) |
| Learn the tool that automates all of this | [53-Frida](../../53-Frida/README.md) |
