# Lab 02 — Run the hardening checklist, and write it up honestly

> **Objective:** compile one source file six ways, audit every result against the chapter's
> checklist, then write the same observation up twice — once as the finding it is not, and once as
> the impact context it is. The second half of this lab is the one that matters.

**Prerequisites:** [Lab 01](lab-01-elf-by-hand.md),
[15-Native-Code §3.14](../README.md#314-the-mitigation-set-in-full) and
[§5.7](../README.md#57-honest-severity--the-section-other-chapters-cite)
**Difficulty:** Intermediate
**Time:** 60 minutes
**You will need:** the NDK (this lab is about comparing builds, so the fixtures are essential),
Python 3

---

## Why this lab exists

Two reasons, and the second is the important one.

**First**, hardening is a *build flag*, and the only way to feel that is to change nothing but the
flags and watch the output change. People who have not done this tend to believe hardening is a
property of the code.

**Second**, a hardening checklist is the most over-reported thing in mobile security. Automated
scanners emit one finding per missing mitigation, at Medium or High, and clients arrive with a list
of forty "vulnerabilities" that are forty missing mitigations in one library. Being the person who
can explain, precisely and without hedging, why thirty-eight of them are not findings is worth more
than most exploits. Part 5 makes you practise it.

---

## Setup

```bash
# host
export ANDROID_HOME="$HOME/Android/Sdk"
cd 15-Native-Code/examples
./build-fixtures.sh /tmp/ch15-fixtures
```

Read [`hardening-demo.c`](../examples/hardening-demo.c) before you start. It is about 120 lines and
every one of its six numbered blocks exists to make a specific point in this lab. In particular
notice:

- `check_password` has a `char buf[64]` and calls `strcpy` — the canary's whole reason for existing;
- `build_command` allocates with a **caller-supplied** size, so FORTIFY cannot help it;
- `g_logger` is a function pointer in `.data`, which RELRO does not protect;
- `on_load` is a constructor, so `.init_array` is never empty;
- `internal_checksum` is `visibility("hidden")` and `public_checksum` is not.

---

## Part 1 — The comparison table

### Task 1.1 — run the checker across three builds

```bash
# host
cd /tmp/ch15-fixtures
python3 ~/…/15-Native-Code/scripts/elf-harden-check.py \
    libdemo-default.so libdemo-hard.so libdemo-weak.so | grep -E '^\[|====='
```

### Task 1.2 — fill this in from your own output

| Check | `default` | `hard` | `weak` |
|---|---|---|---|
| PIE | | | |
| NX / non-executable stack | | | |
| W^X across `PT_LOAD` | | | |
| RELRO | | | |
| Stack canaries | | | |
| `_FORTIFY_SOURCE` | | | |
| Text relocations | | | |
| RPATH / RUNPATH | | | |
| 16 KiB page compatibility | | | |
| Imports worth reading | | | |
| Constructors before `JNI_OnLoad` | | | |

<details>
<summary>Reference results (NDK r25c, clang 14.0.7, API 21)</summary>

| Check | `default` | `hard` | `weak` |
|---|---|---|---|
| PIE | ok | ok | ok |
| NX | ok | ok | **MISSING — RWE** |
| W^X | ok | ok | ok |
| RELRO | **full** | **full** | **MISSING — none** |
| Stack canaries | **MISSING** | ok | **MISSING** |
| `_FORTIFY_SOURCE` | **MISSING** | ok — 2 | **MISSING** |
| Text relocations | ok | ok | ok |
| RPATH / RUNPATH | none | none | none |
| 16 KiB | **MISSING — 0x1000** | ok — `0x4000` | **MISSING — 0x1000** |
| Imports worth reading | 3 | **1** | 3 |
| Constructors | 1 | 1 | 1 |

</details>

### Task 1.3 — three questions about that table

**Q1. Why does the `default` build have full RELRO and NX but no canary and no FORTIFY?**

<details>
<summary>Answer</summary>

Because they come from different places. RELRO and non-executable stack are defaults of the
**linker driver** as Android's clang configures it. Stack protection and `_FORTIFY_SOURCE` are
**compiler flags that the NDK's build systems add** — `android.toolchain.cmake` for CMake,
`default-build-commands.mk` for `ndk-build`. `build-fixtures.sh`'s "default" build invokes the
compiler driver directly and gets neither.

This is a genuinely useful thing to know in an engagement: an app whose native code is built by a
hand-written script rather than through CMake or `ndk-build` will frequently be missing the compiler-
side mitigations while having the linker-side ones. That pattern in the checker output is a hint
about how the app is built. See [§4.4](../README.md#44-where-the-hardening-defaults-come-from--and-a-surprise-worth-knowing).

</details>

**Q2. Why does "imports worth reading" *drop* from 3 to 1 in the hardened build?**

<details>
<summary>Answer</summary>

`_FORTIFY_SOURCE=2` rewrote `strcpy` into `__strcpy_chk` and `sprintf` into `__vsprintf_chk`. Those
are different symbols, so the two dangerous imports left the watch list. Only `system` remains,
because FORTIFY has nothing to say about it.

**This is a trap when diffing releases.** If version 2 of a library has a shorter dangerous-import
list than version 1, that may mean the code was fixed — or it may mean somebody turned on FORTIFY
and nothing else changed. Check for `_chk` before you congratulate anybody.

</details>

**Q3. `weak` has an executable stack but W^X is still "ok". Is that a contradiction?**

<details>
<summary>Answer</summary>

No. They are different things.

- **W^X across `PT_LOAD`** asks whether any *segment of the file* is mapped both writable and
  executable. None is, in any of these builds.
- **`PT_GNU_STACK`** describes the permissions of the **thread stack**, which is not a `PT_LOAD`
  segment at all — it is memory the kernel creates.

`-Wl,-z,execstack` sets the `PF_X` bit in `PT_GNU_STACK` only. It does not make any file segment
executable. Conflating the two is a common error in reports.

</details>

---

## Part 2 — Prove the canary claim rather than trusting it

The checker says `hard` has canaries and `default` does not, based on a symbol reference. Verify it
independently, and then find the case where the symbol is a bad proxy.

### Task 2.1 — find the symbol yourself

```bash
# host
python3 ~/…/scripts/elf-inspect.py libdemo-hard.so --dynsyms --grep stack_chk
python3 ~/…/scripts/elf-inspect.py libdemo-default.so --dynsyms --grep stack_chk
```

### Task 2.2 — the false negative

```bash
# host — a library BUILT WITH -fstack-protector-strong
python3 ~/…/scripts/elf-harden-check.py libjnisurface.so | grep -i canary
```

You will see `[MISS] Stack canaries — no reference found`, on a library that
`build-fixtures.sh` compiled **without** disabling stack protection.

Why?

<details>
<summary>Answer</summary>

Because **no function in it qualified**. `-fstack-protector-strong` protects functions that have a
local array, or a local whose address is taken. Every function in `jni-surface.c` is a small leaf
function with neither. The compiler correctly emitted no canary checks, so there is no reference to
`__stack_chk_fail`, so there is no symbol.

This is a **false negative for "hardening is disabled"** and it is exactly why the checker's
`--verbose` output lists three possible causes rather than one:

```bash
python3 ~/…/scripts/elf-harden-check.py libjnisurface.so --verbose | grep -A8 -i canary
```

Writing "compiled without stack protection" in a report on the basis of a missing symbol, without
checking whether any function could have had one, is a mistake you only make once in front of a
client's build engineer.

</details>

### Task 2.3 — the false negative in the other direction

`libdemo-hard.so` has `__stack_chk_fail`. Does that mean `build_command` is protected?

<details>
<summary>Answer</summary>

No. It means **at least one** function is protected. `build_command` has no local array — it
allocates on the heap — so `-fstack-protector-strong` gives it nothing, and a heap overflow would
not be caught by a stack canary anyway.

A symbol reference is a statement about the library. If your finding is about a specific function,
you have to look at that function's prologue and epilogue in a disassembler —
[§6.5](../README.md#65-recognisable-code-patterns) shows the shape.

</details>

---

## Part 3 — What RELRO does and does not protect

### Task 3.1 — confirm full RELRO

```bash
# host
python3 ~/…/scripts/elf-harden-check.py libdemo-hard.so --verbose | grep -A6 RELRO
python3 ~/…/scripts/elf-inspect.py libdemo-hard.so --dynamic | grep -E 'FLAGS|BIND_NOW'
```

You should see `PT_GNU_RELRO` **and** one of `DT_BIND_NOW` / `DF_BIND_NOW` / `DF_1_NOW`. All three
mean the same thing; different linkers emit different combinations, which is why the checker looks
for all three.

### Task 3.2 — find the pointer RELRO misses

```bash
# host
python3 ~/…/scripts/elf-inspect.py libdemo-hard.so --dynsyms --grep g_logger
python3 ~/…/scripts/elf-inspect.py libdemo-hard.so --sections | grep -E '\.data|\.got|\.data\.rel\.ro'
```

`g_logger` is a function pointer. Which section is it in, and is that section inside the RELRO
region?

<details>
<summary>Answer</summary>

`g_logger` is in `.data`, not `.data.rel.ro`, because the program writes to it at run time
(`set_logger`). The `PT_GNU_RELRO` segment covers `.data.rel.ro`, `.init_array`, `.fini_array`,
`.dynamic` and `.got` — but **not** `.data`.

Compare the `PT_GNU_RELRO` `p_vaddr` and `p_memsz` from `--segments` against `.data`'s `sh_addr` from
`--sections`, and you will see `.data` falls outside.

So: this library has full RELRO, and still has a writable function pointer for the entire life of
the process. An attacker with an arbitrary write does not need the GOT. **Full RELRO is not "the GOT
is safe"; it is "the relocated data is read-only".** That distinction belongs in any report where
you cite RELRO as a mitigating factor.

</details>

---

## Part 4 — Stripping, and what it costs

### Task 4.1 — the delta

```bash
# host
python3 ~/…/scripts/elf-inspect.py libdemo-hard.so          --symbols | head -20
python3 ~/…/scripts/elf-inspect.py libdemo-hard-stripped.so --symbols | head -5
python3 ~/…/scripts/elf-inspect.py libdemo-hard-stripped.so --dynsyms --defined-only
ls -l libdemo-hard.so libdemo-hard-stripped.so
```

Answer:

1. How many symbols did `.symtab` have, and how many does the stripped file have?
2. How many symbols does `.dynsym` have, in each file?
3. Is `public_checksum` still findable by name in the stripped file?
4. Is `internal_checksum`?
5. How many bytes did stripping save?

<details>
<summary>Reference answers</summary>

1. Roughly 50 in `.symtab`; the stripped file has **none**, because the section is gone.
2. **Identical** — around 17 in both. `.dynsym` is mapped and required; `strip` cannot touch it.
3. **Yes.** It is `GLOBAL`/`DEFAULT` and therefore in `.dynsym`.
4. **No**, and it was never in `.dynsym` even before stripping, because it is
   `visibility("hidden")`. In the unstripped file it was in `.symtab` as `LOCAL`/`HIDDEN`; stripping
   removed that last trace of the name.
5. About 2 KB on this tiny fixture; on a real multi-megabyte library it is a few per cent.

</details>

### Task 4.2 — find the hidden function anyway

`internal_checksum` has no name in the stripped file. Find its address anyway, using only the
stripped file plus one fact from the unstripped one.

<details>
<summary>Method</summary>

`public_checksum` is exported and calls `internal_checksum` — that is the only thing it does. So:

1. Get `public_checksum`'s address from `.dynsym` in the stripped file.
2. Disassemble a few instructions there and follow the `bl`.

Or, without a disassembler, use the unstripped file to learn that `internal_checksum` sits at a
fixed offset before `public_checksum`, and confirm that the same relative layout holds in the
stripped file — the addresses do not change, because stripping removes only non-mapped sections.

The general lesson: **stripping removes names, not code, and not addresses.** Every function is
still exactly where it was. Landing on an export and following calls is the standard way to reach
everything else, and it is why [57-Ghidra](../../57-Ghidra/README.md) starts from the export list.

</details>

---

## Part 5 — The part that matters: write it up twice

You have now audited a library. Here is a scenario.

> You are testing a banking application. `lib/arm64-v8a/libdemo-weak.so` is one of eleven native
> libraries. Your audit shows: executable stack, no RELRO, no stack canaries, no `_FORTIFY_SOURCE`,
> 4 KiB alignment only, and three dangerous imports (`strcpy`, `sprintf`, `system`). You have **not**
> identified any memory-safety defect in it, and you have **not** established that any
> attacker-controlled data reaches it.

### Task 5.1 — write the bad version

Write the finding the way an automated scanner would. Give it a title, a severity, and two
sentences. Do it properly — the point is to feel how plausible it reads.

<details>
<summary>What it usually looks like</summary>

> **[HIGH] Missing binary protections in `libdemo-weak.so`**
> The native library `lib/arm64-v8a/libdemo-weak.so` was compiled without stack canaries,
> without `_FORTIFY_SOURCE`, and without RELRO, and is linked with an executable stack. These
> missing protections expose the application to memory-corruption attacks including arbitrary code
> execution. **Recommendation:** recompile with `-fstack-protector-strong -D_FORTIFY_SOURCE=2
> -Wl,-z,relro,-z,now,-z,noexecstack`.

Read it back. Every factual statement in it is true. The severity is wrong, the second sentence
asserts an exposure that has not been demonstrated, and the whole thing is one finding covering four
unrelated observations. A build engineer who reads it will fix the flags — which is fine — and
learn that your findings do not need to be believed, which is not.

</details>

### Task 5.2 — apply the rubric

Go through [§5.7](../README.md#57-honest-severity--the-section-other-chapters-cite)'s four questions
for each observation:

| Observation | 1. Is there a memory-safety bug? | 2. Reachable? | 3. Would this mitigation have changed the outcome? | 4. What does the attacker gain? | Severity |
|---|---|---|---|---|---|
| Executable stack | | | | | |
| No RELRO | | | | | |
| No canary | | | | | |
| No FORTIFY | | | | | |
| 4 KiB alignment | | | | | |
| `system` imported | | | | | |

<details>
<summary>Worked answers</summary>

| Observation | Verdict |
|---|---|
| **Executable stack** | Q1 stops you — no bug identified. But this one is still worth reporting on its own, as a **Low** hardening defect: no modern Android build needs it, and it is a one-flag fix. Report it as a hardening defect, not as an exposure |
| **No RELRO** | Q1 stops you. **Informational.** It matters when an arbitrary-write primitive exists |
| **No canary** | Q1 stops you. **Informational, and not a finding.** Fold into a memory-corruption finding if one is ever found |
| **No FORTIFY** | Same. **Informational** |
| **4 KiB alignment** | Not a security observation at all. **Low compatibility defect**, and it belongs in a different section of the report — the app will fail to start on a 16 KiB-page device, which is a release blocker for a reason that has nothing to do with security |
| **`system` imported** | Not a finding; a **pointer to work**. Find the call site and see what builds the command string. If user input reaches it, *that* is the finding, and it is a command-injection finding rather than a hardening one |

</details>

### Task 5.3 — write the good version

Now write it properly. The structure that works:

<details>
<summary>Reference</summary>

> **[LOW] `libdemo-weak.so` is linked with an executable stack**
> `lib/arm64-v8a/libdemo-weak.so` declares `PT_GNU_STACK` with `p_flags = 0x7` (`RWE`), so the
> thread stack is mapped executable. No modern Android build requires this; it is produced by
> `-Wl,-z,execstack` or by hand-written assembly missing a `.note.GNU-stack` marker.
> **Impact:** by itself, none — no memory-safety defect was identified in this library during this
> assessment. Should one exist, an executable stack removes the mitigation that makes injected
> shellcode unusable, materially increasing exploitability.
> **Remediation:** link with `-Wl,-z,noexecstack`.
>
> ---
>
> **[INFO] Hardening observations across native libraries**
> The following mitigations are absent from `libdemo-weak.so`: stack protection
> (`__stack_chk_fail` absent from `.dynsym` and `.symtab`), `_FORTIFY_SOURCE` (no `__*_chk`
> imports), and RELRO (no `PT_GNU_RELRO` segment). **These are not vulnerabilities.** They are
> recorded because they would each increase the severity of a memory-safety defect if one were
> identified in this library in future, and because enabling all three is a build-configuration
> change with no code impact:
> `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro -Wl,-z,now`.
>
> ---
>
> **[LOW — compatibility, not security] Native libraries aligned to 4 KiB only**
> Nine of eleven native libraries have `PT_LOAD` segments aligned to `0x1000`. On devices with
> 16 KiB kernel pages these libraries cannot be loaded and the application will fail to start.
> **Remediation:** `-Wl,-z,max-page-size=16384`.
>
> ---
>
> **[Follow-up required] `system()` is imported by `libdemo-weak.so`**
> The library imports `system`, indicating it constructs and executes a shell command. The call
> site was not reachable from any attacker-controlled input identified during this assessment. If
> the command string incorporates data from an untrusted source, this would constitute a command-
> injection defect; this should be confirmed against the source.

Four separate items, four accurate severities, one of them explicitly not a security finding, and
one flagged as needing information you do not have. That report gets read next time.

</details>

---

## Success criteria

- [ ] You produced the three-build comparison table from your own output
- [ ] You can explain why the `default` build has RELRO but no canary
- [ ] You can explain why the dangerous-import count *drops* when FORTIFY is enabled
- [ ] You found a library built **with** `-fstack-protector-strong` that the checker reports as
      having no canary, and can explain why that is correct
- [ ] You located a writable function pointer that full RELRO does not protect
- [ ] You showed that stripping changes `.symtab` and leaves `.dynsym` untouched
- [ ] You wrote both the bad and the good version of the write-up, and can articulate what is
      wrong with the first in one sentence

---

## Going further

1. **Build a seventh variant** with `-fvisibility=hidden` and compare `.dynsym` sizes. Note how much
   smaller the export table becomes and what that costs an analyst.
2. **Add `-flto` and rebuild.** Watch functions vanish from the symbol table entirely as link-time
   optimisation inlines them.
3. **Run the checker against a real app's libraries** — any app you legitimately have. Count how
   many of the observations you would actually report, and to whom.
4. **Write the CI gate** described in [§9.5](../README.md#95-enterprise--a-reproducible-hardening-baseline-across-a-portfolio):
   compare today's `--json` output against yesterday's and fail only on a `GOOD` → `MISSING`
   transition. Then explain, in two sentences, why the absolute-state version of that gate would be
   turned off by the first team that hit it.

---

## Next

[Lab 03 — Symbols, stripping and `findExportByName`](lab-03-symbols-and-linking.md).
