# Lab 03 — Where hooks fail

> **Objective.** Install four hooks that are *correct* and watch all four accomplish nothing, for
> four different reasons: the callee was inlined, the code was compiled ahead of time, the method was
> never resolved, and you arrived after the event. By the end you will diagnose "my hook did not
> fire" in minutes instead of hours, and you will stop blaming the hooking engine.

**Difficulty:** intermediate → advanced
**Time:** 2 hours
**Prerequisites:** [Lab 02](lab-02-write-an-inline-hook-by-hand.md),
[13-ART §3.15–3.17](../../13-ART/README.md), [17-Libraries](../../17-Libraries/README.md)
**Device used to verify this lab:** `i9000S`, Android 13 / API 33, **unrooted, no frida-server**.
Sections 2, 3 and 5 were executed there. Section 4's managed-layer half requires root and is marked
as unverified.

---

## 0. The rule this lab exists to install

> A hook that installs successfully and produces no change is **not** a broken hook. It is a
> **measurement**, and the thing it measured is that the code path you instrumented is not the code
> path that runs.

Testers who do not internalise this go and debug their tooling. The tooling is fine.

---

## 1. The four failure classes

| # | Failure | Symptom | Where it lives |
|---|---|---|---|
| 1 | **Inlined callee** | Hook fires when you call the function directly, never when the app runs | Compiler, at build time |
| 2 | **AOT-compiled caller** | Managed hook installs, dispatch never reaches the entry point | ART, at install/compile time |
| 3 | **Unresolved target** | `dlsym` returns `NULL`, or the class is not found | Loader, at runtime |
| 4 | **Timing** | Everything is correct; the event already happened | You, at attach time |

They are ordered by how often they waste an afternoon.

---

## 2. Failure 1 — the inlined callee

### 2.1 Make it happen

```bash
# host
cd 65-Hooking/examples
./build-hook-fixtures.sh
adb push $OUT/libinline.so $OUT/hook-that-fails /data/local/tmp/
adb shell chmod 755 /data/local/tmp/hook-that-fails
adb shell /system/bin/linker64 /data/local/tmp/hook-that-fails
```

Measured:

```
lic_is_valid      @ 0x74dc20564c
lic_open_feature  @ 0x74dc205674

== BEFORE ANY HOOK ==
  lic_is_valid("bad")          = 0
  lic_is_valid("PRO-1234")     = 1
  lic_open_feature("bad")      = -1
  lic_open_feature("PRO-1234") = 42

== HOOK lic_is_valid -> always 1 ==
  lic_is_valid("bad")       = 1   <- the hook demonstrably works
  lic_open_feature("bad")   = -1  <- and it changed NOTHING

== HOOK THE CALLER INSTEAD ==
  lic_open_feature("bad")   = 1  <- now the decision changed
```

Read those three blocks slowly. The hook **works** — `lic_is_valid("bad")` returns 1 where it
returned 0. And the caller is completely unmoved.

### 2.2 See why, in the disassembly

```bash
# host
$NDK/llvm-objdump -d $OUT/libinline.so | sed -n '/<lic_is_valid>:/,/^$/p;/<lic_open_feature>:/,/^$/p'
```

Measured:

```
000000000000164c <lic_is_valid>:
    164c: cbz  x0, 0x1670
    1650: stp  x29, x30, [sp, #-16]!
    1654: mov  x29, sp
    1658: adrp x1, ...
    165c: add  x1, x1, #1240
    1660: bl   0x16f0 <strcmp@plt>
    1664: cmp  w0, #0
    1668: cset w0, eq
    166c: ldp  x29, x30, [sp], #16
    1670: ret

0000000000001674 <lic_open_feature>:
    1674: cbz  x0, 0x1694
    1678: stp  x29, x30, [sp, #-16]!
    167c: mov  x29, sp
    1680: adrp x1, ...            <-- the SAME body, inlined
    1684: add  x1, x1, #1240
    1688: bl   0x16f0 <strcmp@plt>
    168c: ldp  x29, x30, [sp], #16
    1690: cbz  w0, 0x169c
    1694: mov  w0, #-1
    1698: ret
    169c: mov  w0, #42
    16a0: ret
```

`lic_open_feature` contains a **copy** of `lic_is_valid`'s body. There is no `bl lic_is_valid`
anywhere. The exported function is, from the caller's point of view, dead code — kept because
something outside this translation unit might call it, and simultaneously inlined because the
compiler could see the body.

This is plain `-O2`. No unusual flags. It is what every release build does.

### 2.3 The one-command diagnostic

```bash
# host
$NDK/llvm-objdump -d $OUT/libinline.so | grep "bl.*<lic_is_valid>"
```

Measured output: **nothing at all**. Zero callers.

`hookability.py` reports the same thing as a warning, without needing a disassembler:

```bash
# host
python3 -B ../scripts/hookability.py $OUT/libinline.so --symbol lic_is_valid
```

```
callers in file : 0
WARNINGS:
  [?] no `bl` in this file targets 0x164c. Either the function is only called from
      another module, or -- far more often at -O2 -- the compiler INLINED its body
      into its callers and this standalone copy is dead.
```

> **⚠️ Warning.** "0 callers" is not proof of inlining. A library legitimately exports functions for
> *other* libraries to call, and those calls are invisible in this file. The signal is strong when
> you also know that a caller in the *same* file makes the decision — which is exactly the
> `lic_open_feature` case. Read the caller, do not just count.

### 2.4 This is the same finding chapter 18 made, from the other direction

[18-ARM §5.4](../../18-ARM/README.md) patched `lc_verify_signature` to `return 1`, verified it
returning 1, and found that `lc_decrypt_flag` still refused — because clang had inlined the check and
the patched standalone copy is called by nothing. That is the single most useful teaching artefact in
either chapter: **a patch that provably works, against a function that provably no longer matters.**

Hooking inherits the problem **unchanged**, because a hook is a patch with better ergonomics. Nothing
about redirecting control flow helps when there is no control flow to redirect.

### 2.5 What to do instead, in order of preference

1. **Hook the caller.** The decision still gets consumed somewhere. Find where it is *used*, not
   where it is *computed*. Demonstrated in the third block of §2.1.
2. **Hook what the inlined copy still calls.** The inlined body here still goes through the PLT to
   `strcmp`. A PLT/GOT hook reaches it even though an inline hook on `lic_is_valid` does not. This
   is the trick the CTF in [Lab 04](lab-04-ctf-the-honest-trampoline.md) is built on.
3. **Patch the inlined copy at its address inside the caller.** Works; does not scale. The compiler
   may have inlined it into six callers, each with different register allocation.

### 2.6 Exercise

Build `libinline.c` at `-O0` and repeat §2.1.

```bash
# host
$NDK/aarch64-linux-android21-clang -shared -O0 -fPIC -o /tmp/libinline-O0.so libinline.c
$NDK/llvm-objdump -d /tmp/libinline-O0.so | grep "bl.*<lic_is_valid>"
```

**Predict first:** how many callers will you find, and what does that tell you about testing your
hooks against a debug build of the target?

<details>
<summary>Answer</summary>

You will find one. At `-O0` clang inlines nothing, so `lic_open_feature` really does call
`lic_is_valid` and the hook works perfectly.

The lesson is uncomfortable and important: **a hook validated against a debug build proves nothing
about the release build.** The inlining decision is the single largest behavioural difference between
them from an instrumentation point of view, and it is invisible in the source. If you develop your
Frida script against a debug APK the developer gave you, re-verify every hook against the shipping
artefact.

</details>

---

## 3. Failure 2 — the AOT-compiled caller

### 3.1 The managed-layer analogue of inlining

ART does the same thing at the Java level. When `dex2oat` compiles a method ahead of time, it may
inline a callee's body into the caller's compiled code. After that, the caller does not dispatch
through the callee's `ArtMethod`, so replacing
`entry_point_from_quick_compiled_code_` — the managed hook mechanism, owned by
[13-ART §3.16](../../13-ART/README.md) — changes nothing on that path.

13-ART's four-cause table is the canonical reference and this lab does not restage it. What matters
here is the **structural parallel**:

| Layer | The compiler that inlined it | The dispatch that disappeared | The fix |
|---|---|---|---|
| Native | clang, at build time, `-O2` | `bl <callee>` | Hook the caller; or the PLT call it still makes |
| Managed | `dex2oat`, at install time | Virtual dispatch via `ArtMethod` | Force the method back to the interpreter |

The native case is **permanent** — the `.so` you were given is the `.so` that runs, and no runtime
command un-inlines it. The managed case is **reversible**, and that asymmetry is the single most
useful practical fact in this lab:

```bash
# host — force the whole package back to interpreted execution
adb shell cmd package compile -m verify -f com.your.own.testapp
adb shell am force-stop com.your.own.testapp
```

`-m verify` produces **no compiled code**. Every method runs in the interpreter, every dispatch goes
through the entry point, and every managed hook that was silently bypassed starts firing.

> **🔍 Pentester's Note.** When a managed hook does not fire, run that command *before* you debug
> anything else. It costs one command and thirty seconds, and it resolves three of 13-ART's four
> documented causes.

### 3.2 Exercise (no device required)

For each symptom, name the cause and the fix, from 13-ART's table:

| Symptom | Cause | Fix |
|---|---|---|
| Hook installed, never fires | ? | ? |
| Hook fires sometimes, not always | ? | ? |
| Hook fires, but the app still takes the old branch | ? | ? |
| `ClassNotFoundException` inside the hook | ? | ? |

<details>
<summary>Answers</summary>

| Symptom | Cause | Fix |
|---|---|---|
| Never fires | The method was inlined into its caller; no call remains | `cmd package compile -m verify -f`, or hook the caller |
| Fires sometimes | Some call sites inlined, others not | Force deoptimisation |
| Fires but old branch taken | A compiled caller baked in the old result | Force interpretation |
| `ClassNotFoundException` | The class is loaded by a non-default `ClassLoader` | Enumerate class loaders — see [53-Frida](../../53-Frida/README.md) |

Three of the four fixes are the same action. That is why the command in §3.1 is worth memorising.

</details>

### 3.3 Honest limitation

This section was **not executed**. The attached device is unrooted with no `frida-server`, so no
managed hook could be installed to observe failing. The mechanism and the fixes are cited from
13-ART, which derived them; nothing here is presented as a fresh measurement.

---

## 4. Failure 3 — the target does not exist yet

### 4.1 Symbols that are not there when you look

```bash
# host
adb shell /system/bin/linker64 /data/local/tmp/hook-that-fails
```

Now imagine the library had not been loaded. `dlsym` returns `NULL`, and a hook installer that does
not check will happily patch address zero.

The three ways a target fails to exist at attach time:

| Cause | What you see | What to do |
|---|---|---|
| The library is not loaded yet | `dlsym` → `NULL`, `Module.findExportByName` → `null` | Hook `dlopen`/`android_dlopen_ext` and install on load |
| The symbol is not exported | `dlsym` → `NULL` even though the function exists | Find it by offset from the module base; there is no name to ask for |
| The class was never resolved | `ClassNotFoundException` | Enumerate class loaders; the class may be in a dynamically loaded DEX |

### 4.2 Prove the second one

```bash
# host
$NDK/llvm-readelf --dyn-syms $OUT/libguard.so | grep -c FUNC
$NDK/llvm-readelf --syms     $OUT/libguard.so | grep -c FUNC
```

A stripped release library exports only what its author chose to export. Static functions — including
almost every interesting internal check — are invisible to `dlsym` entirely. You address them by
`module_base + file_offset`, which means you must first establish the module base at runtime and the
offset statically, and the two must be for **the same build**.

> **🧠 Mental Model.** `dlsym` answers "what did the author publish?". It does not answer "what
> functions exist?". Static analysis answers the second question; only the running process answers
> where they landed.

### 4.3 Exercise

`libguard.so`'s `guard_check` is exported. Make it `static`, rebuild, and answer:

1. Does `dlsym(h, "guard_check")` still work?
2. Does the function still exist in the file?
3. How would you hook it now?

<details>
<summary>Answer</summary>

1. No — `dlsym` returns `NULL`. It is gone from `.dynsym`.
2. Almost certainly not, in this specific case: with nothing else calling it, the compiler will
   discard the whole function. Add a caller and it survives.
3. Locate it statically (`llvm-objdump -d`, or `llvm-readelf --syms` if `.symtab` survived), record
   its file offset, then at runtime compute `module_base + offset`. The module base comes from
   `dl_iterate_phdr`, `/proc/self/maps`, or `Process.findModuleByName().base`. Everything downstream
   — relocation, patching, cache flushing — is identical to Lab 02; only the *finding* changed.

</details>

---

## 5. Failure 4 — the timing problem

### 5.1 The event already happened

This is the failure that produces the most confident wrong conclusions, because everything about the
hook is correct and the output is simply empty.

A native library can act before you can possibly attach:

| Stage | Runs when | Can you hook before it? |
|---|---|---|
| `DT_PREINIT_ARRAY` | Before any other initialiser in the executable | Only by controlling the loader |
| `.init_array` | At `dlopen`, before `System.loadLibrary` returns | Only by hooking `dlopen` first |
| `JNI_OnLoad` | Immediately after load, called by the runtime | Yes, if you hooked `dlopen` |
| First call to a native method | Whenever the app calls it | Yes, comfortably |

[17-Libraries](../../17-Libraries/README.md) measured the `.init_array` window: the constructors run
**inside** `dlopen`, so by the time `System.loadLibrary("foo")` returns to Java, everything the
library wanted to do at load time has already happened. If your hook installs when the Java code
starts, you missed it.

### 5.2 Prove it locally

`libvault.c` in this directory has an `__attribute__((constructor))` that captures a checksum at load
time. Build it and observe:

```bash
# host
cd 65-Hooking/labs
./build-ctf.sh
adb push $OUT/libvault.so $OUT/vault-runner /data/local/tmp/
adb shell chmod 755 /data/local/tmp/vault-runner
adb shell /system/bin/linker64 /data/local/tmp/vault-runner 0000
```

The constructor has already run before `main` gets control. Any hook installed by `main` is too late
to influence what the constructor recorded — though, as Lab 04 explores, it is not too late to
influence what the *checker* later reads.

### 5.3 The general fix: hook the loader, not the loaded

You cannot install a hook inside a library before it exists. You *can* install a hook on the thing
that creates it:

```javascript
// Frida REPL — install BEFORE the target library loads
Interceptor.attach(Module.findExportByName(null, 'android_dlopen_ext'), {
    onEnter: function (args) { this.path = args[0].readCString(); },
    onLeave: function (retval) {
        if (this.path && this.path.indexOf('libtarget.so') !== -1) {
            // The library is now mapped and its .init_array HAS run.
            // You are as early as this mechanism allows.
            installMyHooks();
        }
    }
});
```

Note the honest limitation encoded in that comment: `onLeave` fires **after** `dlopen` returns, and
`.init_array` ran inside it. To beat a constructor you must be in the process before the library
loads at all — which on Android means Zygisk, injecting into Zygote. See
[62-Magisk](../../62-Magisk/README.md).

To beat `JNI_OnLoad`'s `RegisterNatives`, hook `RegisterNatives` itself in the JNI function table,
which is reachable as soon as you are in the process. See [16-JNI §3.8](../../16-JNI/README.md).

### 5.4 Exercise

An app performs a root check in a `static { }` block of the class that contains its login logic. You
attach with `frida -U -n com.example.app` after the app is already on screen. Your hook on the check
method never fires.

1. Why not?
2. What would you change?
3. Under what circumstance would attaching late still work?

<details>
<summary>Answer</summary>

1. A `static` initialiser runs once, at class initialisation, which happened when the class was first
   touched — long before you attached. The method ran exactly once and will not run again.
2. Spawn rather than attach: `frida -U -f com.example.app`, which starts the process suspended and
   lets you install hooks before any app code runs. This single flag resolves the majority of
   "my hook never fires" reports.
3. If the *result* of the check is re-read later — stored in a field, or re-evaluated per screen —
   you can hook the consumer instead of the producer. That is the same "hook where the decision is
   consumed" move as §2.5, arriving from a different direction.

</details>

---

## 6. A diagnostic order that works

When a hook does not do what you expected, work down this list. It is ordered by cost.

1. **Did the hook install?** Print the address you patched and the bytes before and after. An engine
   that silently no-ops is worse than one that throws.
2. **Did it fire?** Log unconditionally on entry. "It fired but did nothing" and "it never fired" are
   different problems with no overlap.
3. **If it never fired — is anything calling the target?**
   `llvm-objdump -d lib.so | grep "bl.*<name>"`, or `hookability.py`'s caller count. Zero callers
   plus a caller that makes the decision equals inlining.
4. **If it never fired and it is a Java method —** `cmd package compile -m verify -f`, force-stop,
   retry.
5. **If it never fired and the target loads late —** spawn instead of attach; hook `dlopen`.
6. **If it fired but nothing changed —** you are hooking a producer whose consumer no longer asks.
   Find the consumer.
7. **Only now** suspect the hooking engine.

> **🔍 Pentester's Note.** Steps 1 and 2 are the ones people skip, and they are the two that
> distinguish every subsequent branch. Instrument your instrumentation.

---

## 7. Success criteria

- [ ] You produced a hook that provably works on a function and provably changes nothing, and you can
      explain the disassembly that makes both statements true.
- [ ] You can name the one-command static diagnostic for inlining and state its limitation.
- [ ] You can state why the native inlining case is permanent and the managed one is reversible, and
      give the command that reverses it.
- [ ] You can list the four stages of native library initialisation in order and say which of them
      you can still beat once the app is running.
- [ ] You can explain why `frida -U -f` and `frida -U -n` produce different results for a `static { }`
      block.
- [ ] You reached for the diagnostic order in §6 before blaming a tool.

---

## 8. Cleanup

```bash
# host
adb shell rm -f /data/local/tmp/libinline.so /data/local/tmp/hook-that-fails \
                /data/local/tmp/libvault.so /data/local/tmp/vault-runner
find 65-Hooking -name '*.so' -o -name '*.o' -o -name '__pycache__'
```

The `find` must print nothing.
