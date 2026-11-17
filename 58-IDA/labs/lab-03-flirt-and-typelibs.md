# Lab 03 — FLIRT and type libraries

> **Objective.** Build byte-pattern signatures from a static archive you compiled, measure which
> functions produce strong signatures and which produce almost none, and explain the result — which
> is the opposite of what most people expect. Then do the same job from the other end, with type
> libraries, and understand why the two mechanisms exist side by side.

| | |
|---|---|
| **Difficulty** | Intermediate |
| **Time** | 2 hours |
| **Needs an IDA licence?** | **No** for the measurement, which is the substance. **Yes** for the final `sigmake` step, and the lab tells you exactly what you are missing and what to do instead |
| **Needs a device?** | No |
| **You come out with** | A `.pat` file, three measured pattern strengths, and an argument you can defend about why ARM signatures are weaker than x86 ones |

---

## 0. The problem, with a number

You are handed a stripped `libfoo.so`. It has 8,000 functions. Perhaps 300 of them are the
application's own logic; the other 7,700 came from statically-linked BoringSSL, protobuf, curl and
the C++ standard library. Nothing in the binary marks the boundary.

Reading 7,700 functions to find 300 is not a plan.

> **Definition**
> **FLIRT** — Fast Library Identification and Recognition Technology — puts the correct name on a
> library function inside a stripped binary. It matches each function's **first 32 bytes** against a
> database of patterns built from the library's object files, with any byte the linker would rewrite
> masked out, plus a CRC over what follows and the function's total length.

> **Mental Model**
> **FLIRT's value is subtractive.** It does not tell you which function is interesting. It tells you
> which 7,700 are not, so that the 300 that remain are a list a human can read. "How many functions
> did the signatures name?" is therefore a better first question than "what did they name them?" — the
> first is a coverage measurement and the second is trivia.

This lab uses a fixture where you know the ground truth exactly: three functions came from a static
archive, and the rest did not.

---

## 1. Setup

```bash
# host
cd 58-IDA/examples
OUTDIR=/tmp/ch58 ./build.sh
export NDKBIN="$HOME/AppData/Local/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin"
```

You now have two things that matter here:

| File | Role |
|---|---|
| `/tmp/ch58/libcrcutil.a` | **The library you HAVE symbols for.** Signatures are built from this |
| `/tmp/ch58/libsession.so` | **The target you have NO symbols for.** Signatures are applied to this |

That direction is the whole mechanism and people reliably get it backwards.

### 1.1 Confirm the direction

```bash
# host — the archive has symbols
"$NDKBIN/llvm-nm" /tmp/ch58/libcrcutil.a

# host — the target does not
"$NDKBIN/llvm-nm" /tmp/ch58/libsession.so 2>&1 | head -2
```

**Journal entry.** Write one sentence explaining why you cannot build patterns from
`libsession.so` itself.

<details>
<summary>Check yourself</summary>

A pattern needs a *name* to associate with the bytes. Names come from `STT_FUNC` symbols with a size,
which live in `.symtab` — and `--strip-all` removed `.symtab` entirely. A stripped binary has bytes
and no names, which is precisely the problem FLIRT solves; it cannot also be the solution.

</details>

---

## 2. Build the patterns

```bash
# host
cd 58-IDA
python3 -B scripts/01-make-flirt-pat.py /tmp/ch58/libcrcutil.a --explain
```

> **Warning — what this script is**
> [`../scripts/01-make-flirt-pat.py`](../scripts/01-make-flirt-pat.py) implements the published `.pat`
> grammar and **was executed** — its `ar` and ELF parsing is verified against `llvm-nm` and
> `llvm-readelf`, and every line it emits round-trips through its own parser. Its **CRC column has
> never been checked against `sigmake`**, because FLAIR ships only with an IDA licence and IDA is not
> installed on the machine where this chapter was written. Treat the pattern and length columns as
> correct and the CRC as structurally right and numerically unconfirmed. If you own FLAIR, section 6
> tells you the one command that closes the gap.

### 2.1 Read the format

Each line is:

```text
<PATTERN, 64 hex chars>  <ALEN>  <ACRC>  <TLEN>  :<OFF> <NAME>
```

| Field | Width | Meaning |
|---|---|---|
| `PATTERN` | 64 chars | The first 32 bytes. `..` marks a byte the linker may rewrite |
| `ALEN` | 2 hex | How many bytes after the first 32 the CRC covers. Stops at the first variant byte, and at `0xFF` |
| `ACRC` | 4 hex | The CRC16 over those bytes |
| `TLEN` | 4 hex | The function's total length |
| `:OFF NAME` | | A public name at that offset inside the function |

A further field, `^OFF NAME`, records a name the function *references* — how FLIRT tells apart two
functions with identical bodies that call different things.

### 2.2 The measured result

This is what the run produces. **Look at it before reading the analysis**, and try to predict which of
the three has the strongest signature.

```text
architecture      : AArch64
functions found   : 3  (0 skipped by --min-size)
round-trip parse  : all 3 lines OK

ch58_crc32       from 02-crcutil.o     size  292 bytes
   masked in the first 32 bytes: +0x00, +0x01, +0x02, +0x03, +0x04, +0x05,
     +0x06, +0x07, +0x08, +0x09, +0x0a, +0x0b, +0x0c, +0x0d, +0x0e, +0x0f,
     +0x14, +0x15, +0x16, +0x17
   CRC covers 12 byte(s) after the pattern, value 0x6576

ch58_fnv1a64     from 02-crcutil.o     size   56 bytes
   nothing masked in the first 32 bytes -- a strong pattern
   CRC covers 24 byte(s) after the pattern, value 0x2F8B

ch58_hex         from 02-crcutil.o     size   72 bytes
   masked in the first 32 bytes: +0x04, +0x05, +0x06, +0x07, +0x10, +0x11,
     +0x12, +0x13
   CRC covers 40 byte(s) after the pattern, value 0x0115
```

And the lines themselves:

```text
................................0A070037........0C6490520CB7BD72 0C 6576 0124 :0000 ch58_crc32
E80300AAA06484D24084B0F2809CD3F2407EF9F2010100B4693680D20920C0F2 18 2F8B 0038 :0000 ch58_fnv1a64
E20100B4........08040091E90302AA........2B004039290500F16BFD44D3 28 0115 0048 :0000 ch58_hex
```

---

## 3. The analysis — why the intuitive answer is wrong

### 3.1 Task: rank them

Before reading on, rank the three by signature strength and write your reasoning down.

Most people rank `ch58_crc32` first, because it is the table-driven CRC-32 — the function with a
famous constant, the one everybody says is easy to spot.

### 3.2 The measurement says otherwise

| Function | Informative bytes in the pattern | CRC bytes | Verdict |
|---|---:|---:|---|
| `ch58_crc32` | **12 of 32** | 12 | **Weakest.** Two thirds of the pattern is `..` |
| `ch58_fnv1a64` | **32 of 32** | 24 | **Strongest.** Nothing masked at all |
| `ch58_hex` | 24 of 32 | 40 | Middling |

### 3.3 Why

**`ch58_crc32` is masked because it references globals.** Its prologue computes the addresses of the
lookup table and the "table ready" flag, and on AArch64 that means `adrp`/`add` pairs — each of which
carries a relocation the linker rewrites at link time. Five relocated instruction words, twenty bytes,
gone.

The distinctive constant does not help, because in this build the table is computed at first use
rather than being a static initialiser. **The polynomial `0xEDB88320` is in the code, not in the
pattern's first 32 bytes**, and FLIRT only looks at the first 32.

**`ch58_fnv1a64` is unmasked because it references nothing.** Its two magic constants are immediates,
materialised with `movz`/`movk` chains. An immediate is not a relocation. Look at its pattern line:
`A06484D24084B0F2809CD3F2407EF9F2` is four instructions building `0xCBF29CE484222325` sixteen bits at
a time, and every byte of it is fixed.

### 3.4 The general rule

> **Under the Hood — why AArch64 is structurally worse for FLIRT than x86**
> On x86, a relocated value is usually a 4-byte absolute address embedded in a longer instruction. Mask
> it and you lose four bytes; the opcode survives and still discriminates.
>
> On AArch64 every instruction is exactly four bytes, and the relocated field lives *inside* the
> instruction word, sharing it with the opcode bits. FLIRT's format is byte-granular — there is no way
> to say "these eleven bits vary" — so **the whole instruction word must be masked, opcode included.**
> A function whose prologue touches three globals loses twelve of its first thirty-two bytes to
> relocations that only actually varied in a handful of bits.
>
> That is a structural property of the format meeting the architecture, not a criticism of any
> signature database. It is also why the `^OFF REFNAME` referenced-name field matters more on ARM than
> on x86: it recovers discriminating power that masking threw away.

### 3.5 Deliverable

Write a paragraph answering: *given two candidate library functions to build a signature for, which
properties make one a better signature than the other?* Your paragraph should mention relocations,
the 32-byte window, and function length.

<details>
<summary>A model answer</summary>

A good FLIRT candidate is long enough that its length is discriminating, has few or no relocations in
its first 32 bytes, and has at least a few dozen non-variant bytes after the window so the CRC has
something to cover. Functions that build large constants from immediates are ideal. Functions that
begin by taking the addresses of globals are poor, and on AArch64 they are much poorer than the same
function would be on x86, because each relocation costs a whole four-byte instruction word rather than
a four-byte operand. Very short functions are poor regardless, because their length carries little
information and the CRC covers nothing. And a function whose entire first 32 bytes are masked cannot
be matched by pattern at all — the script warns when it produces one.

</details>

---

## 4. Verify the pattern against the target by hand

You do not need IDA to prove the pattern would match. You need the bytes.

### 4.1 Find the candidate in the stripped target

You know from lab 01 that `libsession.so` still exports the three archive functions by name — they
were compiled with default visibility. That is convenient for checking but not representative, so do
it the hard way: find `ch58_fnv1a64`'s bytes in the target **without** using its name.

```bash
# host — extract the unmasked pattern from the .pat line
PAT="E80300AAA06484D24084B0F2809CD3F2407EF9F2010100B4693680D20920C0F2"
echo "$PAT" | sed 's/../& /g'
```

Now search the target for those bytes:

```bash
# host — dump the target's .text as hex and look for the sequence
"$NDKBIN/llvm-objdump" -s -j .text /tmp/ch58/libsession.so \
  | tr -d ' \n' | grep -o -i "${PAT:0:32}" | head
```

**Deliverable.** Did the first 16 bytes of the pattern appear in the stripped target? Then confirm the
address:

```bash
# host — the honest cross-check, using the name you were not supposed to use
"$NDKBIN/llvm-nm" -D --defined-only /tmp/ch58/libsession.so | grep fnv
```

### 4.2 Try it with the weak pattern

Repeat with `ch58_crc32`'s pattern. Its first 32 bytes begin with 16 masked bytes, so you have nothing
to search for at the start. **That is the measurement made tangible:** a pattern whose leading bytes
are all variant gives a byte search no purchase at all, and it is why FLIRT's CRC and length fields
exist as tie-breakers rather than as extras.

---

## 5. Type libraries — the same job from the other end

FLIRT names functions. **Type libraries give them prototypes**, and the two are complementary: a name
tells you not to read a function, a prototype tells the decompiler what its arguments are so that
*every caller* becomes readable.

> **Definition**
> A **type library** (`.til`) is a compiled collection of C declarations — structures, unions, enums,
> typedefs and function prototypes — that IDA can load into a database and apply. Ghidra's equivalent
> is a `.gdt` data type archive. Chapter 57 §3.8 covers the concept in depth and this lab does not
> restate it.

### 5.1 The measurement that motivates it

```bash
# host — the imports this library will resolve at load time
"$NDKBIN/llvm-nm" -D -u /tmp/ch58/libsession.so
```

You should see `memcpy`, `memset`, `strlen`, `abort` and `__cxa_*` entries. Each of those is a
function whose prototype the decompiler cannot derive but that carries real type information:

| Import | Prototype | What it propagates |
|---|---|---|
| `memcpy` | `void *memcpy(void *, const void *, size_t)` | Two pointers and a **size** — and a size that came from outside is where bugs live |
| `strlen` | `size_t strlen(const char *)` | Its argument is a **C string**, which types the field it came from |
| `memset` | `void *memset(void *, int, size_t)` | Gives you `sizeof` for a structure — lab 02's rule 3 |

### 5.2 Task: prove that one prototype does work

Look at `session_init` and identify the call to `strlen`. Then answer: **which structure field does
that single prototype type for you?**

```bash
# host
"$NDKBIN/llvm-objdump" -d --disassemble-symbols=session_init /tmp/ch58/libsession-unstripped.so \
  | grep -B4 -A4 strlen
```

<details>
<summary>Check yourself</summary>

`strlen`'s argument is the `user` parameter, not a structure field — but the `memcpy` immediately
after it writes into `s + 0x20`, and its length is clamped against `#31`. Between them: `+0x20` is a
32-byte buffer holding a NUL-terminated string. One prototype (`strlen`) established "this is a C
string"; the other (`memcpy`) plus the clamp established the destination and its size. Neither fact is
derivable from the raw instructions without knowing what those two functions do.

</details>

### 5.3 Building one for Android

The header worth having is the NDK's `jni.h`, for the reasons chapter 57 §3.8 gives at length.

```bash
# host — find it
ls "$ANDROID_NDK/toolchains/llvm/prebuilt/"*/sysroot/usr/include/jni.h
```

**In IDA:** *File → Load file → Parse C header file…* (`Ctrl+F9`).
**In Ghidra:** *File → Parse C Source…*.

> **Warning**
> Parsing `jni.h` directly frequently fails on the first attempt in **both** tools, because the header
> pulls in platform definitions the parser does not have. The symptom is a long list of parse errors
> and a type library missing exactly the struct you wanted — and it is easy not to notice, because the
> parse *partially* succeeds.
>
> Two fixes, in order of preference. Write a small wrapper header that defines the handful of macros
> the parser complains about and then `#include`s `jni.h`. Or extract `JNINativeInterface`, `_JNIEnv`,
> `JNINativeMethod` and the `j*` typedefs into a standalone header of your own and parse that. The
> second is uglier and reliable.
>
> **Always check afterwards that the type you wanted actually exists**, rather than assuming the parse
> worked.

### 5.4 Task: minimal `jni.h` extract

Write a header containing just enough to type a JNI function, and parse it. Something like:

```c
/* minimal-jni.h -- enough to type a Java_* function's parameters.
   The full JNINativeInterface has ~230 entries in a specification-mandated
   order; chapter 57 section 3.8 tabulates the offsets that matter. */
typedef signed int    jint;
typedef signed char   jbyte;
typedef unsigned char jboolean;
typedef long long     jlong;
typedef void *        jobject;
typedef jobject       jclass;
typedef jobject       jstring;
typedef jobject       jbyteArray;

struct JNINativeInterface;
typedef const struct JNINativeInterface *JNIEnv;

typedef struct {
    const char *name;
    const char *signature;
    void       *fnPtr;
} JNINativeMethod;
```

Then set the fixture's JNI entry point's prototype:

```c
jint Java_com_pentest_ch58_Session_nativeSelfTest(JNIEnv *env, jobject thiz);
```

**Deliverable.** State what changed in the decompilation, and what did **not**. (In this fixture, very
little changes, because the entry point ignores both JNI parameters. That is itself the lesson: a type
is only valuable where it is *used*, and chapter 57's dramatic before-and-after happens because its
fixture makes fifteen JNI calls. Applying a type and seeing no change is not a failure; it is
information about the function.)

---

## 6. What you cannot do here, and what to do instead

The final step of the real FLIRT workflow needs FLAIR, which ships only with an IDA Pro licence:

```bash
# host -- ONLY if you have FLAIR
pelf /tmp/ch58/libcrcutil.a /tmp/ch58/crcutil.pat
sigmake -n"ch58 crcutil" /tmp/ch58/crcutil.pat /tmp/ch58/crcutil.sig
cp /tmp/ch58/crcutil.sig "$IDADIR/sig/arm/"
# then in IDA: View > Open subviews > Signatures, Insert, pick it
```

> **Warning**
> This repository will not tell you where to obtain FLAIR other than with a licence, and will not
> point at cracked builds or key generators for IDA or any other commercial tool. If you do not have a
> licence, the free equivalents are below and they are genuinely usable.

### 6.1 If you have FLAIR — the one command worth reporting back

```bash
# host
pelf /tmp/ch58/libcrcutil.a /tmp/ch58/pelf.pat
diff <(sort /tmp/ch58/pelf.pat) <(python3 -B scripts/01-make-flirt-pat.py /tmp/ch58/libcrcutil.a | sort)
```

That diff answers the one open question in this chapter: whether
[`../scripts/01-make-flirt-pat.py`](../scripts/01-make-flirt-pat.py)'s CRC16 matches FLAIR's. The
script's header says the column is unconfirmed. If you close that gap, it is a real contribution.

### 6.2 If you do not have FLAIR

| Free equivalent | What it does |
|---|---|
| **Ghidra's Function ID (FID)** | The same idea: hash function bodies with operands masked, look them up. Build databases from an NDK sysroot. Chapter 57 §3.6 defines it |
| **Sort the function list by size** | Crude and effective. Application logic is usually large; the small unnamed functions are accessors, thunks and destructors |
| **Cross-reference density** | A function called from fifty places across the binary is library code. One called from one place is application logic |
| **String proximity** | Library functions cluster with the strings from their own translation unit |
| **Compile the candidate library yourself and diff** | If you suspect zlib, build the same version with the same NDK and compare function sizes and prologues. Crude, but it costs ten minutes and it either works immediately or it does not |

That last one deserves emphasis. You know the target's toolchain from
`.note.android.ident` and the `.comment` section:

```bash
# host — what compiler built this?
"$NDKBIN/llvm-readelf" -p .comment /tmp/ch58/libsession.so
```

Matching the compiler version is what makes a byte-level comparison viable at all.

---

## 7. Success criteria

| # | Criterion |
|---|---|
| 1 | You can state which direction signatures flow, and why a stripped binary cannot be a source |
| 2 | You produced a `.pat` file with three lines and can read every field |
| 3 | You predicted which function had the strongest signature **before** looking, and can explain why the intuitive answer is wrong |
| 4 | You can explain, in terms of instruction encoding, why AArch64 masking costs more than x86 masking |
| 5 | You found the unmasked pattern's bytes in the stripped target by hand |
| 6 | You showed that the weak pattern gives a byte search no purchase |
| 7 | You named three imports whose prototypes carry propagatable type information |
| 8 | You wrote a minimal `jni.h` extract and parsed it |
| 9 | You can say why applying a type and seeing no change is informative rather than a failure |
| 10 | You can name three free techniques for separating library code from application code |

---

## 8. What to carry forward

- **Signatures flow from a library you have symbols for to a target you do not.**
- **FLIRT looks at the first 32 bytes**, masks anything the linker rewrites, and uses a CRC and a
  length as tie-breakers.
- **On AArch64 a masked relocation destroys the whole instruction word**, opcode included. ARM
  signature coverage is structurally thinner than x86 coverage.
- **A distinctive constant table does not make a function easy to signature.** Measured: the CRC-32
  lost 20 of its first 32 bytes; the table-free FNV-1a lost none.
- **The useful output is a coverage number**, not a name list. "Signatures named 6,200 of 8,000" tells
  you how much of the binary you can stop worrying about.
- **A type library gives prototypes, and one prototype propagates through every caller.**
- **Applying a type and seeing no change is information**, not failure.

---

| Next | |
|---|---|
| [Lab 04 — CTF: the function that does not matter](lab-04-ctf-the-function-that-does-not-matter.md) | Five flags, each a trap that has cost this repository real time |
| [Chapter README §3.7](../README.md) | The FLIRT section this lab measures |
| [57-Ghidra §3.6](../../57-Ghidra/README.md) | Function ID, the free equivalent |
