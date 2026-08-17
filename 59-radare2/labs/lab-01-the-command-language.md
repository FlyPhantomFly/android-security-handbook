# Lab 01 — The command language

**Difficulty:** Beginner
**Time:** 1–2 hours
**Prerequisites:** [02-Linux-Basics](../../02-Linux-Basics/README.md),
[15-Native-Code](../../15-Native-Code/README.md), [Chapter 59 §3.2](../README.md#32-the-command-language-taught-as-a-grammar)

---

## Why this lab exists

Almost everyone who abandons radare2 abandons it in the first ten minutes, and they all fail the same
way: they type `?`, get several hundred lines of what looks like arbitrary two-letter commands, and
conclude the tool is hostile.

It is not arbitrary. It is a grammar with about a dozen root verbs, a small set of narrowing letters,
a handful of universal suffixes, and four operators. Once you hold those in your head you can
*derive* commands you have never been taught, which is the only way anyone actually uses this tool —
nobody memorises six hundred commands.

**This lab is the one focused hour that makes radare2 usable for the rest of your career.** It
deliberately teaches you almost nothing about Android. It teaches you to read and construct commands.
Lab 02 applies that to real libraries.

> **⚠️ On the state of this chapter**
> radare2 was **not installed** on the machine where this chapter was written, so every radare2
> command here is marked **📘 Unverified** — transcribed from the tool's documentation and source,
> not executed. Everything stated about the *binary* you will be looking at is **✅ Measured** with
> the Android NDK's LLVM tools, and each such claim says so.
>
> If a command in this lab behaves differently from what is written, **the tool is right**. Note the
> difference and fix the chapter.

---

## Objective

By the end you will be able to:

1. Decompose any radare2 command into verb, narrowing letters and suffix, and say what it will do.
2. Use `?` to navigate to a command you have never seen, without a search engine.
3. Use the four operators — `@`, `@@`, `~`, `|` — and explain what each replaced.
4. Move around a binary with `s` and understand why the prompt shows an address.
5. Construct, unaided, the exact commands that
   [37-RootDetection](../../37-RootDetection/README.md) §8.4 and
   [39-EmulatorDetection](../../39-EmulatorDetection/README.md) §8.4 use.

---

## Setup

### 1. Install radare2

```bash
# host (Linux/macOS) -- from git, which is what the project recommends
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
r2 -v
```

```bash
# host (Debian/Ubuntu) -- older, fine for this lab
sudo apt-get install -y radare2
```

Confirm before continuing:

```bash
r2 -v
rabin2 -v
```

If either says "command not found", stop and fix that first. Nothing below will work.

### 2. Build the target

```bash
# host -- builds OUT OF TREE into $HOME/ch59-build; writes nothing into the repository
cd 59-radare2/examples
./build.sh
```

You want `libr2target.so` from that build. It is small on purpose — small enough that you can hold
the whole thing in your head while you learn the commands.

> **✅ Measured** — the target as built by `examples/build.sh` with
> `aarch64-linux-android21-clang` from NDK 25.2.9519653 at `-O2 -Wall -Wextra`, zero warnings.
> `llvm-readelf -S` reports `.text` at address `0x18bc`, file offset `0x8bc`, size `0x250` — that is
> **592 bytes, 148 AArch64 instructions in the entire library.** `llvm-nm -D --defined-only` reports
> six exported functions.
>
> **Read the addresses out of your own build**, from `build-report.txt` in the build directory.
> Editing a comment in the source moves every address in this document.

---

## Part 1 — The prompt is a cursor (15 minutes)

Open the library:

```bash
# host
r2 ~/ch59-build/libr2target.so
```

You get a prompt like:

```
[0x000018bc]> 
```

**That number is the current address**, and it is the single most important thing on the screen.
Almost every command operates *here* unless you tell it otherwise. radare2 is a text editor whose
document happens to be a binary, and this is the cursor.

Try these in order and watch the prompt:

```
# 📘 Unverified
[0x000018bc]> s 0x1000          # seek to an absolute address
[0x00001000]> s+16              # forward 16 bytes
[0x00001010]> s-                # undo the last seek (like a browser's back button)
[0x00001000]> s-                # undo again
[0x000018bc]> s entry0          # seek to the entry point
[0x000018bc]> s sym.lt_gate     # seek to a named symbol
```

### Checkpoint 1

Answer without scrolling up:

- What does `s-` do, and what is the difference between `s-` and `s -16`?
- Why does `s sym.lt_gate` work when you never told radare2 what `lt_gate` is?

<details>
<summary>Answers</summary>

- `s-` undoes the previous seek — it walks backwards through seek *history*. `s -16` seeks to an
  address 16 bytes lower. They look similar and do completely different things; the space matters.
- `sym.lt_gate` is a **flag** — a name bound to an address. radare2 created it automatically when it
  parsed the ELF's dynamic symbol table. Flags are covered in §3.5 of the chapter; every symbol,
  string and section becomes one.

</details>

---

## Part 2 — Root verbs (20 minutes)

There are about a dozen roots. These are the ones that matter:

| Verb | Means | Domain |
|---|---|---|
| `a` | analyse | functions, cross-references, the call graph |
| `i` | info | everything parsed from the file: headers, symbols, strings |
| `p` | print | render bytes as something readable |
| `s` | seek | move the cursor |
| `w` | write | modify bytes |
| `f` | flag | name an address |
| `e` | eval | configuration |
| `S` | Sections | (capital S — lowercase `s` is seek) |
| `V` | Visual | full-screen mode |
| `q` | quit | |

Run each of these and read the output before moving on. Do not skim:

```
# 📘 Unverified
[0x0]> iI          # binary info: arch, bits, stripped, hardening flags
[0x0]> iE          # exports
[0x0]> ii          # imports
[0x0]> iz          # strings in data sections
[0x0]> il          # linked libraries
[0x0]> iS          # sections
```

### What you should see, and why

> **✅ Measured** — the ground truth for each command, established with LLVM tools:
>
> | Command | What it must report |
> |---|---|
> | `iE` | Six functions: `JNI_OnLoad`, `Java_com_pentest_ch59_Native_staticCheck`, `lt_gate`, `lt_probe_paths`, `lt_verify_license`, `main` |
> | `il` | Two libraries: `libc.so` and `libdl.so` |
> | `iS` | `.rodata` at `0x690` size `0x50`; `.text` at `0x18bc` size `0x250`; `.plt` at `0x1b10`; `.data.rel.ro` at `0x2ba0` |
> | `iz` | Five strings, listed below |
>
> The complete string content of the library is **fifty bytes**:
>
> ```
> /system/xbin/su
> com/pentest/ch59/Native
> (Ljava/lang/String;)I
> dynGate
> gate=%d\n
> ```

Look at that string list for a moment, because it is the whole lesson of static triage in miniature.
Five strings tell you: the library checks for `su` (root detection), it registers a native method
called `dynGate` on class `com.pentest.ch59.Native` taking a String and returning an int, and it
prints a result. You have not decoded a single instruction.

> **🔍 Note on `/system/xbin/su`**
> The source file **XOR-encrypts** that string specifically so it will not appear here. At `-O2` the
> compiler evaluated the decode at compile time and stored the plaintext anyway. That is a measured
> finding, not a mistake in the example — chapter §3.8 and §5.3 explain it, and lab 02 makes you
> reproduce it. For now, just note that the "protection" is visibly absent.

### Checkpoint 2

Without looking anything up, predict what each of these does, then run it:

```
# 📘 Unverified
[0x0]> ie
[0x0]> izz
[0x0]> iSS
```

<details>
<summary>Answers</summary>

- `ie` — entry points. `e` narrows `i` to "entrypoints".
- `izz` — strings in the *whole file*, not only data sections. Doubling a letter widens the scope.
  Compare the count with `iz`; `izz` will find strings in `.comment` (the compiler version banner)
  and the section-name table that `iz` skips.
- `iSS` — segments (ELF program headers) rather than sections. Same doubling idea.

The point is that you predicted these correctly from the pattern. That is the grammar working.

</details>

---

## Part 3 — `?` is how you find everything (15 minutes)

**This is the most important part of the lab.**

`?` is not a command. It is a suffix meaning *"explain this prefix"*. Every level of the tree
responds to it.

```
# 📘 Unverified
[0x0]> ?           # the root verbs
[0x0]> a?          # everything under "a"
[0x0]> af?         # everything under "af"
[0x0]> afl?        # the variants of "afl"
[0x0]> i?          # everything under "i"
[0x0]> p?          # everything under "p"
[0x0]> w?          # everything under "w"
```

Spend ten minutes here. Genuinely. Type `a?`, read it, pick a command that looks interesting, append
`?` to it, and descend. This is the skill; everything else in this chapter is an application of it.

### Exercise 3.1 — derive a command you were never taught

Using only `?`, find the command that:

1. Lists functions **as JSON**.
2. Renames the function at the cursor.
3. Shows information about the *current* function.
4. Lists the *local variables* of the current function.

<details>
<summary>Answers</summary>

1. `aflj` — `afl` plus the universal `j` suffix.
2. `afn <newname>` — analyse, function, name.
3. `afi` — analyse, function, info.
4. `afv` — analyse, function, variables.

Note that you did not memorise any of these. You navigated `a?` → `af?` and read.

</details>

### Exercise 3.2 — the universal suffixes

These attach to nearly any command:

| Suffix | Effect |
|---|---|
| `j` | JSON — **the scripting suffix** |
| `q` | quiet: values only |
| `*` | output as radare2 commands, replayable into another session |
| `,` | a sortable table |
| `?` | help |

Try each on the same base command and compare:

```
# 📘 Unverified
[0x0]> iE
[0x0]> iEj
[0x0]> iEq
[0x0]> iE*
```

`iE*` is the one to think about. Its output is a list of `f` (flag) commands. Feed that text into a
*different* r2 session and that session now knows these names. **The command language is also the
save format.** There is no project file format to learn. That design idea is why `r2pipe` (chapter
§3.11) is a five-line API.

---

## Part 4 — The four operators (30 minutes)

This is where radare2 stops being a command line and starts being fast.

### 4.1 — `@` runs a command somewhere else

```
# 📘 Unverified
[0x0]> pd 5 @ sym.lt_gate       # disassemble 5 instructions there
[0x0]> px 32 @ 0x690            # hex dump 32 bytes of .rodata
[0x0]>                          # ...and the cursor never moved. Check the prompt.
```

Without `@` you would need three commands: `s` there, run it, `s -` back. `@` is a *temporary* seek
and it composes with everything.

Run `pd 5 @ sym.lt_gate` and then look at the prompt. It is unchanged. That is the whole feature.

### 4.2 — `~` is grep, built in

```
# 📘 Unverified
[0x0]> iE~Java              # only lines containing "Java"
[0x0]> iE~!main             # lines NOT containing "main"
[0x0]> iz~su,dyn            # lines containing "su" OR "dyn"
[0x0]> iE~?                 # COUNT the lines instead of printing them
[0x0]> iE~[0]               # column 0 of each line
```

`~?` is quietly excellent. `afl~?` is "how many functions did you find", as a bare number, with no
post-processing.

Why an internal grep when the shell has one? Three reasons: it works inside visual mode where there
is no shell; it works on Windows; and `~[N]` understands *columns*, which is what makes the iterator
in 4.3 possible.

### 4.3 — `@@` is a for-loop

```
# 📘 Unverified
[0x0]> aa                        # some analysis, so there are functions to iterate
[0x0]> afi @@ sym.*              # run "afi" once per symbol flag
[0x0]> pdf @@ fcn.*              # disassemble every discovered function
[0x0]> ? @@= 0x18bc 0x1900       # run once per listed address
```

| Form | Iterates over |
|---|---|
| `@@ glob` | every flag matching the glob |
| `@@= a b c` | the literal addresses given |
| `@@f` | every function |
| `@@b` | every basic block in the current function |
| `@@i` | every instruction in the current function |
| `@@c:cmd` | every address in the **output** of `cmd` — the general form |

`@@c:` is the one to remember. Any command that emits addresses can drive any other command.

### 4.4 — `|` and `>` are the ordinary shell ones

```
# 📘 Unverified
[0x0]> iz | wc -l
[0x0]> aflj > functions.json
```

### Exercise 4.1 — combine all four

Write **one** command that disassembles five instructions at every place the library calls
`access`. You will need analysis first.

<details>
<summary>Answer</summary>

```
# 📘 Unverified
[0x0]> aa
[0x0]> pd 5 @@= `axt sym.imp.access ~[1]`
```

Decomposed:

- `axt sym.imp.access` — cross-references **to** the `access` PLT stub.
- `~[1]` — column 1 of that output, which is the address column.
- `` ` ` `` — command substitution: run that and use the text.
- `@@=` — iterate over the resulting list of addresses.
- `pd 5` — at each one, print five instructions.

> **✅ Measured** — the ground truth is a **single** call site.
> `llvm-objdump -d libr2target.so` shows exactly one `bl` to `access@plt`:
>
> ```
>     192c: 8d 00 00 94   bl   0x1b60 <access@plt>
> ```
>
> inside `lt_probe_paths`. If your command prints one block of disassembly around `0x192c`, it
> worked. If it prints nothing, you forgot `aa` — see the trap below.

</details>

> **⚠️ The trap that costs everyone an hour**
> `axt` needs analysis to have run. On a freshly opened binary it returns **nothing, silently**, and
> an empty result looks exactly like "there are no cross-references". If `axt` gives you nothing,
> your first move is `aa`, not a conclusion. Confirm analysis happened with `afl~?` — a non-zero
> function count.

---

## Part 5 — Reading the commands other chapters gave you (15 minutes)

Three chapters of this repository hand you radare2 commands. Until now they were opaque. Decompose
each one *before* reading the answer.

### 5.1 — From [37-RootDetection](../../37-RootDetection/README.md) §8.4

```
iz~su
ii~access
axt @@ str.*su*
afl~Java_
```

<details>
<summary>Decomposition</summary>

| Command | Verb | Narrowing | Operator | Means |
|---|---|---|---|---|
| `iz~su` | `i` info | `z` strings | `~su` grep | data strings containing "su" |
| `ii~access` | `i` info | `i` imports | `~access` grep | imports containing "access" |
| `axt @@ str.*su*` | `a` analyse | `xt` xrefs-to | `@@ glob` iterate | for every flag named `str.*su*`, list what references it |
| `afl~Java_` | `a` analyse | `fl` function list | `~Java_` grep | discovered functions whose name contains `Java_` |

Nothing memorised. Four commands, four verbs, three operators.

</details>

### 5.2 — From [39-EmulatorDetection](../../39-EmulatorDetection/README.md) §8.4

```
is~system_property
axt sym.imp.__system_property_get
iz~qemu,goldfish,ranchu
pdf @ sym.check_env
```

<details>
<summary>Decomposition</summary>

- `is~system_property` — symbols, grepped.
- `axt sym.imp.__system_property_get` — **the high-value one.** Every cross-reference to the PLT stub
  for that import. Because all calls to an imported function within one library funnel through a
  single stub, this is a *complete* list of call sites in this binary. One command tells you whether
  the app reads one property or thirty, and from how many distinct functions.
- `iz~qemu,goldfish,ranchu` — strings matching any of three words (`,` is OR).
- `pdf @ sym.check_env` — disassemble that function, cursor unchanged.

</details>

### 5.3 — From [67-BypassingProtections](../../67-BypassingProtections/README.md) §8.4

```
iS~init_array
axt sym.imp.abort
```

<details>
<summary>Decomposition and why these two specifically</summary>

- `iS~init_array` asks: **does this library run code at load time?** Functions in `.init_array`
  execute when the dynamic linker maps the library — before `JNI_OnLoad`, before any Java code calls
  in, and before an analyst's breakpoints are set. Anti-debug and string decryption live there for
  exactly that reason.
- `axt sym.imp.abort` finds every `abort()` call site. The insight is to search for the **response**
  rather than the check: an app has many checks and few ways of reacting, so finding the reactions
  and walking backwards is faster.

</details>

---

## Part 6 — Naming things (10 minutes)

Analysis you do not write down is analysis you will do twice.

```
# 📘 Unverified
[0x0]> aa
[0x0]> s sym.lt_probe_paths
[0x0]> afn probe_su_path          # rename the FUNCTION here
[0x0]> f my.note 0 @ 0x1924       # bind an arbitrary name to an address
[0x0]> f~my.                      # list your own flags
[0x0]> f*                         # dump ALL flags as replayable commands
[0x0]> f- my.note                 # remove one
```

`f*` is how you carry a day's work to another binary, into a report, or into a colleague's session.

**Save your work:**

```
# 📘 Unverified
[0x0]> Ps mylab                   # save a project
[0x0]> q
$ r2 -p mylab                     # reopen it with all names and analysis intact
```

On this 592-byte target that is pointless. On a library with 6 MB of `.text` it is the difference
between a two-second start and a coffee break, every single morning.

---

## Part 7 — Visual mode (15 minutes)

```
# 📘 Unverified
[0x0]> aa
[0x0]> s sym.lt_gate
[0x0]> VV                         # graph view of this function
```

In the graph view:

| Key | Does |
|---|---|
| `hjkl` or arrows | move |
| `+` / `-` | zoom |
| `g` | seek to a flag by name |
| `x` | cross-references *to* here; pick one and jump |
| `q` | back out one level |
| `:` | run an ordinary r2 command without leaving |

> **✅ Measured** — `lt_gate` has a specific and readable shape, which `llvm-objdump -d` shows:
>
> ```
> 00000000000048a0 <lt_gate>:            (addresses from the r2gate executable build)
>     48b0: bl    0x481c <lt_probe_paths>
>     48b4: cbz   w0, 0x48c0             ; probe==0 -> continue
>     48b8: mov   w0, wzr                ; else return 0
>     48bc: b     0x48d0
>     48c0: mov   x0, x19
>     48c4: bl    0x4854 <lt_verify_license>
>     48c8: cmp   w0, #0
>     48cc: cset  w0, ne
> ```
>
> In the graph that is **four basic blocks in a diamond**: an entry that calls the probe and
> branches, two arms, and a join. Learn to see that shape — it is the shape of every two-condition
> security gate, and lab 03 is entirely about what it means.

Now press `p` a few times from ordinary visual mode (`V`, not `VV`) to cycle print modes:
disassembly, hex, strings. Each is the same bytes rendered differently — which is the `p` verb's
entire job.

---

## Success criteria

You have finished this lab when you can do all of these **without looking anything up**:

- [ ] Say what `iEj` does, having never been told, by decomposing it.
- [ ] Find the command to list a function's variables, using only `?`.
- [ ] Explain the difference between `s-` and `s -16`.
- [ ] Explain why `axt` returned nothing, and fix it.
- [ ] Write a command that runs `pdf` on every function whose name contains `lt_`.
- [ ] Explain what `iE*` output is *for*.
- [ ] Say what `sym.imp.access` names, and why that makes `axt` on it a complete call list.
- [ ] Count the strings in the target with a single command.

<details>
<summary>Two of the harder answers</summary>

**`pdf` on every `lt_` function:**

```
pdf @@ sym.lt_*
```

**Counting strings:**

```
iz~?
```

</details>

---

## Common problems

| Symptom | Cause | Fix |
|---|---|---|
| `axt` prints nothing | No analysis has run | `aa` first; confirm with `afl~?` |
| `sym.lt_gate` is not found | Analysis not run, or the binary is stripped | `aa`; on a stripped binary use `fcn.<addr>` names or work from `iE` |
| `s -16` gives an error | You meant `s-` (seek history) | The space is significant |
| Commands from a tutorial do not exist | You have rizin, not radare2, or a very different version | Chapter §3.14; `rz-bin` for `rabin2`, etc. |
| Output is full of escape characters when redirected | Colour codes | `e scr.color=0` |
| `pdf` says "no function at this address" | radare2 does not know a function is there | `af` to analyse just this one |

---

## What you learned

- radare2 commands are **verb + narrowing + suffix + operators**, not a vocabulary list.
- `?` after any prefix descends the tree. This is how you find commands, permanently.
- `j` makes almost anything scriptable; `*` makes almost anything replayable.
- `@` relocates a command, `@@` repeats it, `~` filters it, `|` pipes it.
- The prompt is a cursor and most commands are relative to it.
- Cross-references require analysis, and their absence is silent.

---

## Next

[Lab 02 — Triage a real library](lab-02-triage-a-real-library.md) applies the grammar to real
Android system libraries, introduces the cost model that decides when to run analysis at all, and
makes you reproduce the chapter's measured finding that an `-O2` build leaked a string its source
was carefully encrypting.
