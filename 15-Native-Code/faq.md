# 15 — Native Code · FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct; the long
version of each is in [README.md](README.md).

---

### 1. What actually *is* a `.so` file?

A file of machine code and data that the operating system loads into a running program.

Concretely: the first four bytes are `7F 45 4C 46`, which is a byte with the value 127 followed by
the letters `E`, `L`, `F`. After that comes a 64-byte header describing the file, then two tables of
metadata, then the content — instructions for the CPU, constants, string literals, and a list of the
names the file offers to other code and the names it needs from other code.

"`.so`" stands for **shared object**. Shared, because one copy of the code exists in physical memory
however many processes are using it. On Windows the same idea is a `.dll`; on macOS a `.dylib`.

Nothing about the format is compressed, encrypted or obfuscated. It is a container, and it is fully
documented. See [§1.3](README.md#13-what-a-so-actually-is-in-one-paragraph).

---

### 2. Why does an APK have four `lib/` folders, and which one actually runs?

One per CPU architecture — `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`. The same source code,
compiled four times.

**Exactly one runs.** The device reports a prioritised list of architectures it supports
(`getprop ro.product.cpu.abilist`). At install time the package manager picks the highest-priority
one for which the APK has a directory, and uses only that. On any modern phone that is
`arm64-v8a`. The other three are downloaded, stored on disk, and never opened.

Two practical consequences:

- **Analyse `arm64-v8a`.** Analysing the 32-bit copy because it is smaller is a real mistake people
  make; the two builds can differ in inlining and occasionally in features.
- Those unused copies are why App Bundles and split APKs exist — they let Google Play ship only the
  one the device needs.

See [§3.16](README.md#316-abis-and-the-four-directories).

---

### 3. Why does `strings` show nothing useful?

Four possibilities, and you can tell them apart in about a minute.

1. **You are looking at the whole file.** Running `strings` over an entire library returns symbol
   names, section names, dependency names and compiler banners — hundreds of lines of noise. Look at
   `.rodata` only: `python3 scripts/elf-inspect.py x.so --strings --min 12`.
2. **The library is small and genuinely has few constants.** A 40 KB helper library with twenty
   strings is normal.
3. **The strings are encrypted** and decrypted at run time. This is the interesting case, and the
   giveaway is **density**: a normal 2 MB library has thousands of printable strings. A 2 MB library
   with sixty has encrypted them, and you now know before you open anything else that you are
   dealing with a protected target.
4. **Your minimum length is too high or too low.** `-n 4` drowns you in noise; `-n 20` misses most
   keys.

String density relative to file size is the single most informative number in triage.
See [§6.6](README.md#66-what-obfuscation-and-packing-do-to-the-file).

---

### 4. What does "stripped" mean, and what is still left?

`strip` removes the `.symtab` and `.strtab` sections, plus `.comment` and any `.debug_*`. Those hold
every symbol the compiler emitted — including internal `static` functions that were never meant to be
called from outside — along with the compiler banner and any DWARF debug information.

**What it cannot remove is `.dynsym`**, the *dynamic* symbol table. The dynamic linker needs it at
run time to connect a call in one library to a definition in another. Take it away and the library
does not load.

So a stripped library still tells you:

- every function it **exports**, by name — including every statically registered `Java_*` JNI entry
  point;
- every function it **imports**, by name — so you can see it calling `strcpy`, `system`, `ptrace`;
- every dependency, from `DT_NEEDED`;
- its `SONAME`, its build ID, its constructors, and its whole relocation table.

What you lose is the names of *internal* functions, which become `FUN_00004b04` in a decompiler.
That is a genuine inconvenience and it is much less than most developers imagine.

The setting that actually reduces the export table is `-fvisibility=hidden`, not `strip`.
See [§3.6](README.md#36-symbols-dynsym-symtab-and-what-findexportbyname-searches).

---

### 5. Is a missing stack canary a finding?

**No.** It is a missing mitigation, and reporting it as a vulnerability is the fastest way to lose a
client's confidence in everything else in your report.

A stack canary is a random value the compiler puts between local variables and the saved return
address, checked on the way out of the function. It only ever does anything when a *linear stack
overflow that reaches the return address* already exists. If the library has no such bug, the canary
would never have fired, and its absence changed nothing.

There is also a false-negative trap: "no `__stack_chk_fail` symbol" has **three** possible causes,
and only one of them is "hardening was disabled":

1. compiled without `-fstack-protector*`;
2. compiled **with** it, but no function qualified — `-fstack-protector-strong` only protects
   functions with an array or an address-taken local, so a library of small leaf functions correctly
   gets no canaries;
3. statically linked against a libc that resolves the symbol internally.

The right place for it in a report is as **impact context inside a real memory-corruption finding**:
"…the library is compiled without stack protection, so the overflow overwrites the saved return
address without detection."

The one item on the checklist that comes close to standing alone is an **executable stack**
(`PT_GNU_STACK` with the execute bit set), which no modern Android build needs and which is a
one-flag fix. Report that as a Low hardening defect.

See [§5.7](README.md#57-honest-severity--the-section-other-chapters-cite), which the rest of this
repository cites for severity.

---

### 6. What is the difference between a section and a segment, and why does anyone care?

A **segment** is a run of the file that gets mapped into memory with one set of permissions. The
**loader** reads segments. A **section** is a named region with a purpose — `.text`, `.rodata`,
`.dynsym`. **Tools** read sections.

One segment usually covers several sections: the read-execute segment covers `.text` and `.plt`; the
read-write segment covers `.data`, `.got` and `.init_array`.

Why anyone cares: **the loader never looks at sections at all.** That is why `strip` is safe, why a
packer can delete the entire section header table and leave a file that runs perfectly, and why —
when your tool and the file disagree — the segments are the ones telling the truth. A section header
is a claim; a program header is a contract the loader enforces.

[Lab 05](labs/lab-05-ctf-the-honest-header.md) is built entirely on this distinction.

---

### 7. Why does the address I noted in Ghidra never match what Frida shows me?

Because a shared library has no fixed address. Every address inside it is *relative* to a base the
linker picks at load time, randomised by ASLR.

```text
runtime_address = module_base + file_virtual_address
file_virtual_address = runtime_address - module_base
```

Ghidra shows you file virtual addresses. Frida shows you runtime addresses. Get the base once and
every conversion afterwards is arithmetic:

```javascript
var base = Module.findBaseAddress('libnative.so');
var live = base.add(0x4b04);
```

One trap: when reading `/proc/<pid>/maps` by hand, a library appears as **several** consecutive
lines, one per loadable segment. The base is the start address of the **first** one, the line with
file offset `00000000`. Taking the `r-xp` line instead gives you an address that is wrong by a
constant, which is a uniquely frustrating way to lose an afternoon.

---

### 8. `Module.findExportByName` returns `null` for a function I can clearly see. Why?

It searches `.dynsym`, and only `.dynsym`, of the module you named. Four reasons it comes back empty:

1. **The function is not exported.** A `static` function, or one compiled with
   `__attribute__((visibility("hidden")))`, or a library built with `-fvisibility=hidden`, is never
   in `.dynsym`. It is still in `.text` and still executes; it simply has no run-time name. Reach it
   by offset from an export.
2. **The name is mangled.** `Crypto::decrypt(char const*)` is `_ZN6Crypto7decryptEPKc`, not
   `decrypt`. Use `llvm-cxxfilt`, or filter `Module.enumerateExports()` by substring.
3. **The module is not loaded yet.** Spawn and hook `dlopen` rather than attaching.
4. **You have the module name wrong** — the linker records libraries by `DT_SONAME`, which can differ
   from the file name.

`rpc.exports.find()` in [`scripts/native-map.js`](scripts/native-map.js) prints all four of these as
diagnostics, plus any exports whose names contain your search string.

---

### 9. I stripped my library. Why can Frida still hook it?

Because stripping removes `.symtab`, and Frida reads `.dynsym`. See questions 4 and 8. Stripping and
hooking are almost unrelated.

Even if you removed every symbol — which you cannot, for exports — hooking would still work. Frida
does not need a name; it needs an address. `Interceptor.attach(base.add(0x4b04), ...)` works on a
library with no symbols at all. Names are a convenience for the analyst, not a requirement for the
tool.

If your goal is to make instrumentation harder, symbol removal is close to the least effective thing
you can do. That is a statement about the ceiling of client-side protection, not advice on how to
raise it.

---

### 10. Why do all the `.init_array` entries read as zero when I dump them?

Because you are looking at an AArch64 library.

AArch64 uses `RELA` relocations, which carry their value in an **addend** field. The linker writes
`load_base + addend` into the slot at load time, so the slot in the *file* is left as zero. Read it
straight out of the file and you get a list of zeros — and if you stop there you conclude there are
no constructors, and you miss the first code that runs.

ARM32 uses `REL`, which has no addend, so the value genuinely is stored in the slot and dumping it
works.

Find the real address by looking in `.rela.dyn` for an `R_AARCH64_RELATIVE` relocation whose
`r_offset` equals the `.init_array` address, and reading its addend. The chapter's tool does it for
you and says so:

```text
.init_array at 0x8cd8, 1 entries
      [0] 0x1bf0   (slot is 0 in the file; the value comes from the RELATIVE relocation addend)
```

If the slot is zero **and** there is no matching relocation, the library uses Android's packed
relocation format — use `llvm-readelf -r`.

---

### 11. Why does the app run code before `JNI_OnLoad`, and how do I get in front of it?

Because C++ requires global objects to be constructed before anything uses them, and there is no
`main` in a library. The mechanism is `.init_array`: a list of function pointers the linker calls the
moment it finishes loading the library — **before** `JNI_OnLoad`, and before `System.loadLibrary`
returns to Java.

Legitimate C++ code lands there, which is why the count is rarely zero. So do packers, licence
checks, anti-debug code and integrity checks, precisely because it is the earliest execution
opportunity a library has.

To get in front of it you must **spawn**, not attach:

```bash
frida -U -f com.example.app -l scripts/native-map.js --no-pause
```

Attaching to a running process is always too late — all of it already happened. To see it happening,
hook the loader itself: `rpc.exports.watchload()`.

---

### 12. What is the GOT, and why does everyone want to overwrite it?

When `libnative.so` calls `strcpy`, the address of `strcpy` is not known when `libnative.so` is
compiled — it depends on where `libc.so` happens to be mapped in this process. The compiler has to
emit something.

The solution is one level of indirection. The **GOT** (Global Offset Table) is an array of pointers
in *writable data*; the **PLT** (Procedure Linkage Table) is an array of tiny code stubs, each of
which loads a pointer from its GOT slot and jumps through it. The call site branches to the stub —
a fixed distance the compiler knows — and only the *data* has to be patched at load time.

That means the code pages never need to be writable, and one write patches every call site at once.

Which is exactly why it is a hooking target: every call to `strcpy` from anywhere in `libnative.so`
goes through **one** GOT slot. Change that slot and you have redirected all of them, without touching
a single instruction and without any check on `.text` noticing.

`RELRO` is the countermeasure. See question 13.

---

### 13. My GOT hook does nothing and there is no error. What is wrong?

Almost certainly full RELRO. Check the permission of the slot first:

```javascript
Process.findRangeByAddress(slot).protection      // "r--" means RELRO won
Memory.protect(slot, Process.pointerSize, 'rw-');
```

Android's linker resolves every symbol eagerly at load time and then `mprotect`s the whole relocated
region read-only. The slot you are trying to write is not writable any more.

Two other causes worth checking:

- **Wrong slot.** GOT slots are per-module. Hooking the `open` slot in `libfoo.so` does nothing to
  calls made from `libbar.so`.
- **No slot at all.** If the callee is in the *same* library, the compiler may have emitted a direct
  branch with no GOT involvement.

`Interceptor.attach` avoids the whole problem by patching the function's own entry point, which is
why it is the default.

---

### 14. What is `extractNativeLibs`, and is `true` a finding?

It is a manifest attribute that decides whether native libraries are copied out of the APK at install
time, or mapped directly from inside it.

- `extractNativeLibs="true"`, or the ZIP entry being compressed → the library is extracted to
  `/data/app/~~xxx/<pkg>-n/lib/<arch>/`. It now exists twice on disk.
- `extractNativeLibs="false"` → the library stays in the APK and is mapped straight out of it. This
  requires the ZIP entry to be **stored uncompressed AND page-aligned**, because `mmap` needs
  contiguous unmodified bytes at a page-multiple offset. Either half alone is useless.

**`true` is not a finding.** It is a build configuration with a disk-space cost. Reporting it as a
security issue is a mark against you.

What it *is* good for: knowing where the file lives on the device, which is where you `adb pull` from
— and knowing which copy a self-integrity check is looking at, since apps sometimes verify one copy
while running the other.

---

### 15. What does "16 KiB page" mean and why would my app stop starting?

Android has historically assumed 4 KiB memory pages. Newer devices use 16 KiB kernel pages.

A library's `PT_LOAD` segments declare an alignment (`p_align`). If that is only `0x1000` (4 KiB),
the loader on a 16 KiB-page device cannot honour the segment boundaries, and **the library fails to
load** — which means the app fails to start.

The fix is one link flag: `-Wl,-z,max-page-size=16384`. The check:

```bash
python3 scripts/elf-harden-check.py libnative.so | grep '16 KiB'
```

Report it as a **compatibility defect**, in whatever section of your report holds those. It is not a
security issue, and putting it next to memory-safety observations muddles both. It is nonetheless one
of the highest-value lines the checker produces, because "the app does not start on new hardware" is
a problem everybody agrees about.

---

### 16. `readelf` says this library has no relocations. Is that possible?

Not really — every shared library has relocations, usually thousands.

What has happened is that you are using binutils `readelf` on a library that uses **Android's packed
relocation format** (`DT_ANDROID_REL` / `DT_ANDROID_RELA`, from API 23) or **RELR**
(`DT_ANDROID_RELR` from API 28, standard `DT_RELR` from API 30). Binutils does not decode either, and
reports nothing rather than reporting that it cannot.

Use `llvm-readelf`, which ships in every NDK:

```bash
$ANDROID_HOME/ndk/<version>/toolchains/llvm/prebuilt/<host>/bin/llvm-readelf -r libnative.so
```

This chapter's `elf-inspect.py` does not decode the packed formats either — and says so explicitly
rather than printing zero.

---

### 17. Should I be worried that an app has native code at all?

No. Almost every non-trivial Android app has native code, most of it third-party — image codecs,
crypto, analytics SDKs, game engines, the C++ runtime.

What is worth being interested in:

- **Native code that processes untrusted bytes.** A media, image, font or protocol parser fed by the
  network is where nearly every serious Android memory-corruption vulnerability has been found.
- **An outdated bundled third-party library** that is reachable. This is, in practice, the
  highest-yield native finding on most engagements, and it requires no exploitation skill at all —
  see [17-Libraries](../17-Libraries/README.md).
- **A secret in `.rodata`.** Second highest yield, and it takes ten seconds to check.
- **Security logic moved into native code**, which tells you where the developer thought the
  important checks were.

"This app contains native libraries" is not a finding. "This app decodes downloaded images with a
`libwebp` build from 2021, reached from a chat message" is.

---

### 18. Can I just decompile the `.so` back to C?

Not to the original source, no. Compilation is lossy in ways that cannot be undone: variable names,
comments, types, the distinction between a loop and its unrolled form, and the boundaries of inlined
functions are all gone.

What you *can* get is a decompiler's reconstruction — readable C-like pseudocode that is
semantically close and syntactically nothing like the original. That is genuinely useful, and it is
[57-Ghidra](../57-Ghidra/README.md)'s subject.

What this chapter gets you is everything you should know **before** you open a decompiler: the
architecture (so the decompiler picks the right language), the entry points, whether it is stripped,
what runs at load time, and what the interesting strings and addresses are. Ninety seconds of that
saves an hour of aimless scrolling.

---

### 19. A library is in `/proc/<pid>/maps` but not in Frida's module list. What does that mean?

The library has unlinked itself from the dynamic linker's internal list of loaded objects — the
`link_map` chain that `dl_iterate_phdr` walks and that `Process.enumerateModules()` reads.

`/proc/<pid>/maps` comes from the kernel, which does not consult the process about what to report,
so the mappings are still there with the file name attached.

**The discrepancy is itself the finding.** A library that hides from the loader's own bookkeeping is
not doing so for performance. Fall back to enumerating memory ranges directly:

```javascript
Process.enumerateRanges('r--').forEach(function (r) {
    if (r.file && r.file.path.indexOf('.so') > 0) console.log(r.base, r.file.path);
});
```

---

### 20. Why do these scripts parse ELF by hand instead of using `readelf` or `pyelftools`?

Three reasons, in order of how often they matter.

1. **`readelf` is frequently absent.** It is not on Windows, not in most containers, and not on the
   average corporate laptop image. A tool that shells out to it fails on the machine you happen to
   be sitting at.
2. **Binutils `readelf` is wrong on Android targets.** It cannot decode packed relocations and
   reports zero where there are thousands, which looks like a finding and is a tooling failure.
3. **When a file is hostile, you need a parser you control.** A packed or deliberately malformed
   library is exactly the case where an off-the-shelf tool gives up or answers confidently and
   wrongly. Four hundred lines of Python you understand is the tiebreaker.

The same reasoning produced `17-Libraries/scripts/lib-fingerprint.py` and
`12-DEX-Internals/examples/dex_parser.py`. Writing the parser once is also the fastest way to
actually learn the format, which is why [Lab 01](labs/lab-01-elf-by-hand.md) makes you do it.

---

### 21. What is the single most useful thing to check first, on any `.so`?

`.init_array`, and then the strings in `.rodata`.

```bash
python3 scripts/elf-inspect.py libnative.so --init
python3 scripts/elf-inspect.py libnative.so --strings --min 16
```

The first tells you what runs before anything can observe it. The second finds the hardcoded secret,
which is the most common real finding in Android native code and needs no memory-corruption skill,
no device, and no decompiler.

Everything else — the hardening checklist, the export table, the imports — is worth doing, and is
worth doing after those two.
