# Lab 02 — Anti-analysis in `JNI_OnLoad`, and in the tier below it

**Difficulty:** Intermediate
**Time:** 90–120 minutes
**Chapter:** [38 — Tamper Detection](../README.md) · §3.7–3.12, §4.5, §6.5

---

## Objective

Build the native tier of a tamper detector, prove for yourself that an **ELF constructor runs before
`JNI_OnLoad`**, and then find each check in the compiled `.so` the way an analyst would — by parsing
the ELF rather than by reading the source you just wrote.

By the end you will have:

- Compiled `examples/tamper_check.c` for arm64 with the NDK, warning-free.
- Confirmed, from the ELF itself, that it has exactly one `.init_array` entry, exports `JNI_OnLoad`,
  and imports `ptrace`.
- Understood why the `.init_array` → `JNI_OnLoad` ordering is **structural**, not conventional.
- Located each of the six checks in the disassembly without looking at the C.
- Understood exactly what `ptrace(PTRACE_TRACEME)` does and does not buy.
- Understood why hashing your own `.so` file misses every hook that matters.

---

## Why this lab exists

Chapter 38 §2.2 claims the tier a check runs at "determines what an analyst can and cannot observe",
and §3.12 claims the ordering is structural. Those are exactly the kind of claims that get repeated
without being checked. Fifteen minutes with `llvm-readelf` and a logcat window settles both.

There is also a claim in §3.11 that people find genuinely counter-intuitive:

> Hashing the **file** proves the file on disk is unmodified. It says nothing about memory. And every
> hooking framework in existence works by modifying **memory**.

Part E makes that concrete.

---

## Prerequisites

**Knowledge.** [16-JNI](../../16-JNI/README.md) (the JNI boundary, `JNI_OnLoad`),
[17-Libraries](../../17-Libraries/README.md) (the dynamic linker and `.init_array`),
[15-Native-Code](../../15-Native-Code/README.md), and chapter 38 §3.7–3.12.

**Tools.**

| Tool | Check |
|---|---|
| Android NDK (r21+; r25c used for the reference measurements) | `ls $ANDROID_HOME/ndk/` |
| `llvm-readelf`, `llvm-objdump`, `llvm-nm` (ship with the NDK) | in `toolchains/llvm/prebuilt/*/bin/` |
| `adb` and a device (for Part D) | `adb devices -l` |
| Optionally Ghidra, for Part F | [57-Ghidra](../../57-Ghidra/README.md) |

> **⚠️ Never commit a `.so`**
> `.so`, `.o` and executables are on this repository's artefact blocklist. Everything you build here
> goes to `/tmp`. The last section has the sweep command.

---

## Part A — Read the source, then build it

Read [`../examples/tamper_check.c`](../examples/tamper_check.c) first. Six checks:

| ID | Check | Runs in |
|---|---|---|
| N1 | `TracerPid` from `/proc/self/status` | `JNI_OnLoad`, **and** the constructor |
| N2 | `ptrace(PTRACE_TRACEME)` | `JNI_OnLoad` |
| N3 | `/proc/self/maps` scan | `JNI_OnLoad` |
| N4 | Frida default port 27042 | `JNI_OnLoad` |
| N5 | Digest of our own file, via `dladdr` | `JNI_OnLoad` |
| N6 | Timing of the whole set | `JNI_OnLoad` |
| E0 | `TracerPid`, again | **`.init_array` constructor** |

Build it:

```bash
# host — set these to your NDK and host tag
NDK=$ANDROID_HOME/ndk/25.2.9519653
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin      # or windows-x86_64, darwin-x86_64

$TC/aarch64-linux-android21-clang -shared -fPIC -O2 -Wall -Wextra \
    -o /tmp/libch38.so 38-TamperDetection/examples/tamper_check.c -llog
```

**Checkpoint A.** It must compile with **zero warnings**. The reference build did, at `-O2 -Wall
-Wextra` with NDK r25c. If yours emits warnings, read them — a warning in security-relevant C is
worth reading twice.

> **On Windows / Git Bash**, the compiler is `aarch64-linux-android21-clang.cmd`.

**Question A1.** The file guards every Android-specific include behind `#ifdef __ANDROID__` and
provides a `main()` for non-Android builds. Why would a security-checking library be written to
compile off-device?

<details>
<summary>Answer A1</summary>

So it can be reasoned about, syntax-checked, and unit-tested without an NDK or a phone. A check you
cannot run on your laptop is a check whose logic nobody reviews.

It also lets a reader on a machine with no NDK still do most of this lab with
`cc -fsyntax-only tamper_check.c`.
</details>

---

## Part B — Read the library as an analyst would

Now forget you have the source. This is what you get in a real engagement: one `.so`.

### B1 — Sections

```bash
# host
$TC/llvm-readelf -S /tmp/libch38.so | grep -E "init_array|\.text|\.rodata"
```

Measured on the reference build:

```
  [13] .text        PROGBITS   0000000000001f94 000f94 0008bc 00  AX
  [17] .init_array  INIT_ARRAY 00000000000039d8 0019d8 000008 00  WA
```

**Question B1.** `.init_array` is 8 bytes. On a 64-bit target, how many constructor functions is
that, and how do you find out which function it points at?

<details>
<summary>Answer B1</summary>

Eight bytes is **one** function pointer on a 64-bit target (`sizeof(void*) == 8`). On 32-bit arm it
would be two.

To resolve it, read the 8 bytes at file offset `0x19d8` as a little-endian address and look that
address up in the symbol table:

```bash
# host
$TC/llvm-objdump -s -j .init_array /tmp/libch38.so
$TC/llvm-nm -C /tmp/libch38.so | sort
```

In a stripped library the constructor will have no name, and you jump to the address in a
disassembler instead. That is the normal case in the wild.
</details>

### B2 — Imports and exports

The distinction matters enormously and `strings` cannot make it.

```bash
# host — what does this library CALL (undefined symbols)
$TC/llvm-readelf --dyn-syms /tmp/libch38.so | awk '$7=="UND"{print $8}' | sort

# host — what does it OFFER
$TC/llvm-readelf --dyn-syms /tmp/libch38.so | awk '$7!="UND" && $4=="FUNC"{print $8}' | sort
```

Measured:

```
    13: ...  FUNC  GLOBAL DEFAULT  UND  ptrace@LIBC
    19: ...  FUNC  GLOBAL DEFAULT  UND  dladdr@LIBC
    21: ...  FUNC  GLOBAL DEFAULT   13  ch38_run_all
    22: ...  FUNC  GLOBAL DEFAULT   13  JNI_OnLoad
```

**Question B2.** Why is "this library **imports** `ptrace`" a much stronger statement than "the string
`ptrace` appears in this file"?

<details>
<summary>Answer B2</summary>

An undefined `FUNC` symbol named `ptrace` means the dynamic linker will resolve it at load time
because this library **calls it**. That is a fact about the code.

The string `ptrace` appearing somewhere in the file could be a log message, a symbol name in
`.dynstr` that is never called, an error table, or a coincidence inside a data blob. `strings` cannot
distinguish these.

This is exactly why [`../scripts/tamper-surface-map.py`](../scripts/tamper-surface-map.py) implements
a small ELF reader instead of shelling out to `strings`. Its parser was checked against
`llvm-readelf` on this very library and agreed exactly — one `.init_array` entry, `JNI_OnLoad`
exported, `ptrace` and `dladdr` imported.
</details>

### B3 — Do it with the chapter's own tool

```bash
# host
python3 -B - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location('m', '38-TamperDetection/scripts/tamper-surface-map.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
e = m.Elf(open('/tmp/libch38.so','rb').read())
print('parsed:', e.ok)
print('init_array entries:', e.init_array_entries)
print('anti-debug imports:', [s for s in e.imports if s in ('ptrace','dladdr','fork','syscall')])
print('entry points:', [s for s in e.exports if 'JNI' in s or s.startswith('ch38')])
PY
```

> **⚠️ Use `python3 -B`.** `importlib.util.module_from_spec` writes bytecode regardless of
> `PYTHONDONTWRITEBYTECODE`, and this repository must never contain a `__pycache__`. Sweep afterwards
> if in doubt.

**Checkpoint B.** Your output matches `llvm-readelf`. You have independently verified a tool you are
about to trust in lab 03.

---

## Part C — Prove the ordering

§3.12 claims the constructor runs before `JNI_OnLoad`, structurally. Prove it.

### C1 — From the source of truth

Read, in AOSP:

- `bionic/linker/linker_soinfo.cpp` — `soinfo::call_constructors()` walks `.preinit_array` and
  `.init_array`.
- `bionic/linker/linker.cpp` — the `dlopen` path that calls it **before returning**.
- `art/runtime/java_vm_ext.cc` — `JavaVMExt::LoadNativeLibrary()` calls `android_dlopen_ext`, then
  `dlsym`s `JNI_OnLoad` and calls it.

**Question C1.** From those three files alone, argue that the ordering cannot be otherwise — without
running anything.

<details>
<summary>Answer C1</summary>

`JNI_OnLoad` is looked up with `dlsym` **after** `android_dlopen_ext` has returned. And
`android_dlopen_ext` cannot return until the linker has finished loading the object, which includes
calling every function in `.init_array`.

So the constructor runs inside a call that must complete before the lookup can even begin. There is
no interleaving available: it is a strict happens-before, enforced by the call structure rather than
by convention.

The security consequence, which is the whole reason this matters: any hook installed by a script that
waits for `Java.perform` is installed long after both.
</details>

### C2 — Empirically, on a device

To observe it you need the library loaded by an app. Build the lab-01 app with a `System.loadLibrary`
call added.

Add to `MainActivity` (work on a **copy** of `examples/`, not the repository):

```java
    static {
        try {
            System.loadLibrary("ch38");
        } catch (UnsatisfiedLinkError e) {
            android.util.Log.w(TAG, "native tier not present: " + e.getMessage());
        }
    }
```

Then place the built `.so` where the packager will find it, and rebuild. Using the lab-01 build
script as a base, the library must end up at `lib/arm64-v8a/libch38.so` inside the APK:

```bash
# host — add the .so to the built APK before signing
cd /tmp/ch38lab2
mkdir -p lib/arm64-v8a && cp /tmp/libch38.so lib/arm64-v8a/
python3 -B -c "
import zipfile
z = zipfile.ZipFile('unaligned.apk','a', zipfile.ZIP_DEFLATED)
z.write('lib/arm64-v8a/libch38.so','lib/arm64-v8a/libch38.so')
z.close()"
# then zipalign + apksigner exactly as build.sh does
```

Install, run, and read logcat:

```bash
# host
adb logcat -c
adb shell am start -n com.pentest.ch38.integrity/.MainActivity
sleep 3
adb logcat -d -s CH38N:V CH38:V
```

Expected ordering — and the ordering is the result:

```
CH38N: E0 .init_array constructor  PASS    | TracerPid=0
CH38N: E0 ^ this ran INSIDE dlopen(), before JNI_OnLoad and before any app Java code...
CH38N: JNI_OnLoad entered - running native tier before any app Java code
CH38N: N1 TracerPid              PASS    | TracerPid=0
CH38N: N2 ptrace TRACEME         PASS    | PTRACE_TRACEME succeeded; the tracer slot is now ours
CH38N: N3 maps scan              PASS    | 1180 mappings scanned, no match
CH38N: N4 frida port             PASS    | 127.0.0.1:27042 refused (Connection refused)
CH38N: N5 self file              UNKNOWN | cannot open "..." (uncompressed-in-APK library?)
CH38N: N6 timing                 PASS    | checks took ... us
CH38:  D1 self-signature = PASS  | ...
```

`E0` **always** precedes `JNI_OnLoad entered`, which always precedes the Java-tier `D*` lines.

> **Honest note.** The reference measurements for this chapter compiled and structurally verified the
> library, but did **not** load it from an installed app — see README §7.9. If your ordering differs
> from what is written here, record what you saw; the device wins.

**Question C2.** N5 is likely to report `UNKNOWN | cannot open "..."`. Why, and what does that tell
you about self-file-hashing on modern Android?

<details>
<summary>Answer C2</summary>

With `android:extractNativeLibs="false"` — the default for modern builds — the `.so` is **not
extracted to disk**. It is mapped directly out of the (uncompressed, aligned) APK entry. `dladdr`
reports a path like `/data/app/…/base.apk!/lib/arm64-v8a/libch38.so`, which `fopen` cannot open
because it is not a file.

So the naive "hash my own file" check simply cannot run on a modern packaging configuration. A real
implementation must either parse the APK zip to find its own entry, or hash the mapped pages instead.

`tamper_check.c` returns `UNKNOWN` and says why, rather than returning PASS and pretending. That is
the §5.7 rule — UNKNOWN is not PASS — applied to a case where it genuinely matters.
</details>

---

## Part D — `ptrace(PTRACE_TRACEME)`, understood properly

N2 is the most misunderstood check in the catalogue.

**Question D1.** `check_ptrace_traceme()` returns PASS when `PTRACE_TRACEME` **succeeds**. Is this a
detection or a denial? What is it detecting, if anything?

<details>
<summary>Answer D1</summary>

It is a **denial**, primarily. A process may have at most one tracer; claiming the slot means a later
`PTRACE_ATTACH` from a debugger or from frida-server fails with `EPERM`.

It becomes a **detection** only in the failure case: if the call fails, somebody already holds the
slot. So a single call detects a tracer that was attached *before* the library loaded, and denies one
that would attach after.

Its fatal weakness: `frida -U -f com.target.app` spawns the process under Frida, so the slot is
already taken before the library is even mapped. Anti-debug that assumes it runs first loses to one
command-line flag.
</details>

**Question D2.** The comment warns that calling `PTRACE_TRACEME` twice makes the app detect itself.
Trace through why, and say what a developer must do about it.

<details>
<summary>Answer D2</summary>

The first call succeeds and installs the parent as tracer. The second call finds the slot occupied —
by the relationship the first call created — and fails with `EPERM`. Code that treats "TRACEME
failed" as "somebody is tracing me" therefore fires on its own earlier call.

The developer must call it exactly once per process, which in practice means a `static` guard or a
one-shot in a single `JNI_OnLoad`. It is a surprisingly common bug in libraries that get loaded
twice, or in an app with multiple processes where the check is in shared code.
</details>

### D1 — The watchdog variant

A stronger design forks a child that ptraces the **parent**. Now the check lives in a second process
entirely.

**Question D3.** Why does a forked watchdog defeat an attacker who hooked `ptrace` in the app
process, and what new weakness does it introduce?

<details>
<summary>Answer D3</summary>

The `ptrace` call happens in the **child**, which is a separate process with its own address space.
An `Interceptor.attach` on `ptrace` in the parent does not exist in the child at all.

The new weakness is that the watchdog is a process, and processes are visible and killable. An
attacker can enumerate children (`/proc/<pid>/task`, or just `ps`), kill the watchdog, and continue —
unless the app also notices the watchdog dying, which turns into an arms race about who notices
whose death first.

This is the shape of most anti-analysis escalation: each step is real, each step is defeatable, and
the cost goes up in minutes rather than orders of magnitude.
</details>

---

## Part E — Why file hashing misses what matters

**Question E1.** Suppose N5 were completed: the library hashes its own file and compares against a
baseline stored elsewhere. For each attack, say whether the check catches it.

| Attack | Caught? |
|---|---|
| Patch bytes in `libch38.so` inside the APK, re-sign | ? |
| Let it load, then `mprotect` + overwrite the mapped page | ? |
| Frida `Interceptor.attach` on `check_maps` | ? |
| Patch the GOT so `fopen` resolves elsewhere | ? |

<details>
<summary>Answer E1</summary>

| Attack | Caught? | Why |
|---|---|---|
| Patch in the APK, re-sign | **Yes** — and the signature check caught it too, more cheaply | The file changed |
| `mprotect` + overwrite mapped pages | **No** | The file is untouched. This is what every hooking framework does |
| Frida `Interceptor.attach` | **No** | Same reason: memory, not file |
| GOT patch | **No** | `.text` is byte-identical; only the resolved pointer changed |

Three of four, missed. That is the point of §3.11: file hashing verifies the wrong thing.

The version that catches inline hooks is **mapped-page hashing** (D11 in the catalogue), and it is
the only local check in the whole chapter that costs an attacker hours rather than minutes. It is
also much harder to write correctly — you must exclude relocated regions and the GOT, and handle the
uncompressed-in-APK case from question C2.
</details>

**Question E2.** [18-ARM](../../18-ARM/README.md) records a measurement where a check function was
patched to `return 1`, verified as returning 1, and the protected routine still refused. What
happened, and what does it imply for anyone patching a native integrity check?

<details>
<summary>Answer E2</summary>

The compiler had **inlined** the check into its caller. The standalone function still existed, was
patched, and was called by nobody — the real check was a copy of the same logic sitting inside
`lc_decrypt_flag`.

Implication: after patching a native check, **verify the effect, not the patch**. A patch that
provably works against a function that provably no longer matters is the most convincing kind of
wrong answer. Cross-reference the function before you patch it: if nothing calls it, that is your
warning.
</details>

---

## Part F — Find the checks in the disassembly

Now do it without the source. Open `/tmp/libch38.so` in Ghidra
([57-Ghidra](../../57-Ghidra/README.md)), or use `llvm-objdump -d`.

```bash
# host
$TC/llvm-objdump -d --demangle /tmp/libch38.so | less
```

Find each of these by shape, not by symbol name:

| # | Find | Recognise it by |
|---|---|---|
| F1 | The `.init_array` constructor | Follow the pointer in `.init_array` |
| F2 | The `TracerPid` check | A string reference to `/proc/self/status`, then a `strstr` and a `strtol` |
| F3 | `PTRACE_TRACEME` | A call to `ptrace` with an immediate `0` in the first argument register (`w0` on arm64) |
| F4 | The maps scan | `fopen` of `/proc/self/maps`, then a `fgets` loop with `strstr` against a table of pointers |
| F5 | The port check | `socket`, then `connect`, with `0x69a2` appearing — that is 27042 byte-swapped by `htons` |
| F6 | The self-file hash | `dladdr` on an address inside this library, then `fopen` on the result |

**Question F1.** For F5, `htons(27042)` produces `0x69A2` in the port field. Why does the constant
appear byte-swapped, and what would you grep for if the app used a different port?

<details>
<summary>Answer F1</summary>

`htons` converts host byte order (little-endian on arm64) to network byte order (big-endian). 27042
is `0x69A2`; stored big-endian in the `sockaddr_in`, the bytes are `69 A2`, which a little-endian
disassembler shows as the immediate `0xA269` or as `0x69a2` depending on where you look. Knowing to
look for both forms saves time.

If the port is different, do not grep for a constant at all. Grep for the **call shape**: `socket` →
`connect` with a loopback address (`0x7f000001`, or `htonl(INADDR_LOOPBACK)`). The loopback constant
is the stable part; the port is not.
</details>

**Question F2.** In an obfuscated, stripped library, which of F1–F6 remain findable, and how?

<details>
<summary>Answer F2</summary>

All of them, though with different effort:

- **F1** — `.init_array` is a *section*, not a symbol. Stripping does not remove it. Always findable.
- **F3** — `ptrace` is an **import**, resolved by name by the linker. It cannot be hidden without
  switching to a raw syscall, which changes the shape you look for (an `svc #0` with `x8` = 117 on
  arm64) but does not hide it.
- **F2, F4, F6** — the libc calls are imports too. The *strings* can be encrypted, which is what
  raises the cost: you find the `fopen` call and then have to work out what path it is being given.
- **F5** — same; the call shape survives.

The general rule from §6.3 applies to native code as well as Java: **what crosses a boundary cannot
be renamed.** Imports cross the linker boundary; JNI names cross the runtime boundary. Those are
your anchors.
</details>

---

## Part G — Design exercise

**Question G1.** You are given one hour to add a native tier to a real app. Rank these by
value-per-hour and justify the ranking:

- Port check (N4)
- `TracerPid` polling (N1)
- Maps scan (N3)
- `ptrace(PTRACE_TRACEME)` (N2)
- Mapped-page hashing (D11)
- Reporting every verdict to the server

<details>
<summary>Answer G1</summary>

1. **Reporting to the server.** Highest value by a distance, and it is the cheapest. It is the only
   item that keeps working after everything else is bypassed, and the only one that gives you a
   population signal. §5.8's R5.
2. **Maps scan (N3).** The best cost/benefit of the local checks: minutes-to-hours to evade properly,
   and cheap to implement.
3. **`TracerPid` polling (N1).** Cheap, and polling beats a one-shot. Remember it does not catch JDWP.
4. **`ptrace(TRACEME)` (N2).** Free, denies a class of attach, worthless against `-f`. Take the free
   win, expect nothing.
5. **Mapped-page hashing (D11).** Genuinely the strongest local check — and you will not get it right
   in an hour. Excluding relocations and the GOT correctly is a multi-day job, and a wrong one
   produces false positives on real devices.
6. **Port check (N4).** One flag to evade. Implement it if it is free; do not spend the hour on it.

The ranking's real lesson is that the top item is not a check at all.
</details>

**Question G2.** `JNI_OnLoad` in `tamper_check.c` does **not** return `JNI_ERR` on a FAIL verdict, and
the comment says failing closed is "the right choice in production for exactly the reasons it is the
wrong choice in a lab". Argue both sides.

<details>
<summary>Answer G2</summary>

**For returning `JNI_ERR` in production:** it fails closed. The library refuses to load, so the
protected functionality is unreachable, and there is no window where the app runs with a known-bad
verdict.

**Against:** `System.loadLibrary` throws `UnsatisfiedLinkError`, which is **indistinguishable from a
packaging bug**. A user on an unusual device gets a crash that looks exactly like a broken build, and
your crash reporter fills with a signature you cannot triage. It is also the loudest possible signal
to an attacker: they know instantly which library, and they know the check is in `JNI_OnLoad`.

The better production pattern is to load successfully, record the verdict, and let a *later*
consequence — ideally a server-side one — act on it. That is §3.14's table, and it is why
`LayeredTamperDetector` folds verdicts into key material instead of branching.

**For a lab**, failing closed destroys the exercise: the reader gets a crash instead of a report.
</details>

---

## Success criteria

- [ ] `tamper_check.c` compiles for arm64 with `-Wall -Wextra` and zero warnings.
- [ ] You can show, from `llvm-readelf` alone, that the library has one `.init_array` entry, exports
      `JNI_OnLoad`, and imports `ptrace` and `dladdr`.
- [ ] The mapper's own ELF parser agrees with `llvm-readelf`.
- [ ] You can argue the `.init_array` → `JNI_OnLoad` ordering from the AOSP call structure, without
      running anything.
- [ ] You can explain why `ptrace(PTRACE_TRACEME)` is a denial and when it is worthless.
- [ ] You can state which three of four hooking attacks a file hash misses, and why.
- [ ] You located at least four of the six checks in the disassembly without consulting the C.
- [ ] You can explain why an import is a stronger signal than a string.

---

## Clean up

```bash
# host
rm -f /tmp/libch38.so
rm -rf /tmp/ch38lab2
adb uninstall com.pentest.ch38.integrity 2>/dev/null

# host — the repository must contain no build artefacts
cd 38-TamperDetection
find . \( -name "*.so" -o -name "*.o" -o -name "*.apk" -o -name "__pycache__" \) -print
```

That last command must print nothing.

---

## What to take away

1. **The ordering is structural.** `dlopen` cannot return before the constructors run, and
   `JNI_OnLoad` cannot be looked up before `dlopen` returns. This is not a convention you can hope an
   implementation got wrong.
2. **Imports are evidence; strings are hints.** Parse the ELF. "Imports `ptrace`" and "the word
   ptrace appears" are different claims and only one is actionable.
3. **File hashing verifies the wrong thing.** Three of the four attacks that matter modify memory,
   not files.
4. **`PTRACE_TRACEME` is a denial.** It costs an attacker one flag if they spawn you.
5. **What crosses a boundary cannot be renamed.** Imports cross the linker's boundary; JNI names
   cross the runtime's. Those are your anchors in any stripped, obfuscated binary.

---

## Next

- [Lab 03 — Map before you bypass](lab-03-map-the-detector.md) — apply all of this to apps you did
  not write, and measure how often the tooling is wrong.
- [Lab 04 — CTF](lab-04-ctf-silent-integrity.md).
