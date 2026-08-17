# Lab 02 — Structure recovery

> **Objective.** Turn `ldr w8, [x0, #68]` into `s->state`. You will derive a complete 0x50-byte
> structure from the disassembly alone, write it as C, confirm it at run time, and then **break your
> own answer** by changing the source so that the layout acquires a padding hole — and re-derive it.
> The second half is the part that transfers, because real structures have holes and a recovered
> layout with none is slightly suspicious.

| | |
|---|---|
| **Difficulty** | Intermediate |
| **Time** | 2 hours |
| **Needs an IDA licence?** | **No.** IDA has a one-keystroke shortcut for the first half; the derivation rules are tool-independent and the lab gives you both routes |
| **Needs a device?** | Optional. Section 6 confirms the layout at run time and is worth doing; sections 1–5 do not need one |
| **You come out with** | A C structure declaration, a confirmation that it is right, and a wrong one you can explain |

---

## 0. Why this is the highest-value skill on a stripped library

A function receives a pointer and reads `[x0]`, `[x0, #4]`, `[x0, #8]`, `[x0, #68]`. Until your tool
knows what that pointer points at, every one of those is arithmetic on an opaque address, and no two
of them look related. Supply the structure and the same code becomes `s->magic`, `s->flags`,
`s->issued_at`, `s->state` — and, crucially, **every other function that takes the same pointer becomes
readable at the same time**, because you set the type once.

That is the leverage. It is why chapter 57 §3.11 calls the equivalent step in Ghidra a fixed-point
computation with you inside the loop, and it is why this chapter argues it is the single action most
worth doing well.

> **📖 Definition**
> A **structure** in C is a fixed layout of named fields at known byte offsets from a base address.
> The compiler discards the names and keeps only the offsets, so the machine code contains
> `[x0, #68]` where the source said `s->state`. **Recovering a structure is guessing the mapping
> back** — and it is a guess that can be wrong in a way that stays internally consistent, which is
> what section 6 exists to catch.

---

## 1. Setup

```bash
# host
cd 58-IDA/examples
OUTDIR=/tmp/ch58 ./build.sh
export NDKBIN="$HOME/AppData/Local/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin"
```

For this lab you may use the **unstripped** build, because the exercise is layout recovery, not name
recovery — lab 01 did that. Having the names makes the listings readable while you learn the rules.

```bash
# host
"$NDKBIN/llvm-objdump" -d --disassemble-symbols=session_init \
    /tmp/ch58/libsession-unstripped.so
```

> **⚠️ Warning**
> Do not open [`../examples/03-ground-truth-aarch64.md`](../examples/03-ground-truth-aarch64.md)
> section 9 until section 5 tells you to. That is the answer key for this lab specifically.

---

## 2. The three rules

Everything in this lab is these three rules, applied repeatedly. Learn them and the tool stops
mattering.

### Rule 1 — the instruction names the width

You never guess a field's size. The load or store instruction states it.

| Instruction | Bytes | Signedness |
|---|---|---|
| `ldrb` / `strb` | 1 | unsigned |
| `ldrsb` | 1 | **signed** |
| `ldrh` / `strh` | 2 | unsigned |
| `ldrsh` | 2 | **signed** |
| `ldr w` / `str w` | 4 | unsigned or don't-care |
| `ldrsw` | 4 → 8 | **signed**, sign-extended into an `x` register |
| `ldr x` / `str x` | 8 | |
| `ldr q` / `str q` | 16 | a vector register — often a `memcpy` of a 16-byte block, not a real field |

> **🔍 Pentester's Note**
> The signed forms are worth pausing on. `ldrsw` on a length before a `memcpy` means the length is a
> signed 32-bit value, and a negative length becomes an enormous unsigned size. Chapter 70 owns the
> bug class; the point here is that **the instruction told you the type, and the type is the bug.**
> Chapter 57 makes the same observation about Ghidra's `INT_SLESS` versus `INT_LESS`.

### Rule 2 — a loop bound gives an array length

A `strb`/`ldrb` loop that starts at `base + 0x10` and terminates on `cmp x8, #16` is sixteen bytes at
`+0x10`. The loop bound *is* the array length; you do not have to infer it from spacing.

### Rule 3 — `memset`'s third argument gives `sizeof`

Almost every initialiser starts by zeroing the structure. Find the `memset` (or the inlined
equivalent — a sequence of `stp xzr, xzr` stores) and read the size.

Failing that, the largest offset any function touches, rounded up to the alignment of the widest
field, is a **lower bound** on `sizeof`.

---

## 3. The derivation

Work through these five functions in order. For each, record every `[reg, #N]` access with its width.

```bash
# host
for f in session_init session_step session_seal session_report session_slow_path; do
    echo "=== $f"
    "$NDKBIN/llvm-objdump" -d --disassemble-symbols=$f /tmp/ch58/libsession-unstripped.so \
        | grep -E 'ldr|str|add .*#[0-9]+' 
done
```

Build a table as you go. Yours should end up looking like this shape — the offsets are for you to
fill in:

| Offset | Width | Seen in | How it is used | Therefore |
|---|---|---|---|---|
| `+0x00` | 4 | every function | compared against a constant built by `mov`+`movk` | a magic value |
| | | | | |

### 3.1 Start with `session_init`

This is always the right place to start, because an initialiser touches every field.

Things to look for, in order:

1. **The `memset`.** Its third argument is `sizeof`. Write it down; everything else must fit inside it.
2. **The first store.** A magic value written to offset 0.
3. **A store of a 64-bit argument.** `str x`, so 8 bytes.
4. **`strlen` and `memcpy`.** Their destination is a char array, and the length clamp gives its size.
   Look for a `cmp` against a value one less than a power of two.
5. **A loop writing single bytes.** Its base and bound give you an array.

### 3.2 Then `session_step`

The dispatch function touches the fields that change. Note in particular:

- A 4-byte field loaded, compared against small integers 0 to 3, and stored. That is an **enum**, and
  the constants it is compared against are its values.
- A 4-byte field loaded, incremented by 1, stored. That is a **counter**.
- A 4-byte field manipulated with `orr` and `and` against small powers of two. That is a **bit field**,
  and each constant is a flag. Record them:

```bash
# host — the flag constants, extracted
"$NDKBIN/llvm-objdump" -d --disassemble-symbols=session_step /tmp/ch58/libsession-unstripped.so \
    | grep -E 'orr|and' 
```

`orr w8, w8, #0x2` sets bit 1. `and w8, w8, #0xfffffffd` clears it. You can name four flags from this
function alone.

### 3.3 Then `session_slow_path`

There is exactly one field touched **only** here. Find it. Its existence is why the structure is
`0x50` bytes rather than `0x4c`, and it is the kind of field you miss if you only read the obvious
functions.

### 3.4 Then `session_seal` and `session_report`

These confirm the array bounds and show you which fields are read rather than written.

---

## 4. Write it down

**Deliverable: a C declaration.** Something of this shape, with your own offsets and your own names:

```c
struct session_ctx {
    /* +0x00 */ unsigned int   ???;
    /* +0x04 */ unsigned int   ???;
    /* ...                              */
};                                 /* sizeof = 0x?? */
```

### 4.1 Applying it in IDA

Two routes.

**The manual route**, which works in every tool: `Shift+F1` opens **Local Types**; `Insert` adds a new
type; paste the declaration. Then click the parameter in the pseudocode window and press `Y` to retype
it as `session_ctx *`.

**The shortcut**, which is IDA's genuine convenience: in the pseudocode window, right-click a variable
used as a base pointer and choose **Create new struct type**. Hex-Rays walks every access made through
that variable in the current function and generates a structure with a field at each offset, sized by
the access width. You then rename the fields.

> **⚠️ Warning — the shortcut's limitation, which matters**
> It sees **only the accesses in the current function**. Run it on `session_step` and you get the
> fields `session_step` touches and nothing else — no `user[32]`, because `session_step` never reads
> it. The generated structure will be full of gaps named `field_20`, `field_24`, and it is very easy
> to accept that as the answer.
>
> The discipline is to generate from the *initialiser*, which touches everything, and then extend it
> as other functions reveal more. The rules in section 2 do not have this failure mode, which is why
> this lab teaches them first.
>
> (The feature is documentation-derived; IDA is not installed on the machine where this chapter was
> written, so the exact menu wording may differ on your build.)

### 4.2 Applying it in Ghidra

*Data Type Manager* → right-click your program's archive → *New → Structure*. Add fields at the
observed offsets, using `undefined` padding for the gaps you have not identified. Then `Ctrl+L` on the
parameter. Chapter 57 §3.11 walks it.

### 4.3 With neither

Keep the declaration as documentation and read the listing with it beside you. You lose the automatic
re-rendering, which is real, but the analysis is identical — and you will find that after twenty
minutes you are reading `[x19, #68]` as `state` without help.

---

## 5. Check the static half

Now read section 9 of [`../examples/03-ground-truth-aarch64.md`](../examples/03-ground-truth-aarch64.md).

| # | Criterion |
|---|---|
| 1 | Nine fields, at the right offsets |
| 2 | `sizeof` is `0x50` and you got it from `memset`, not from arithmetic |
| 3 | The 8-byte field at `+0x08` is one field, not two 4-byte fields |
| 4 | The 16-byte array at `+0x10` — you got its length from the loop bound |
| 5 | The 32-byte array at `+0x20` — you got its length from the clamp |
| 6 | You identified the enum at `+0x44` and its four values |
| 7 | You identified the bit field at `+0x04` and at least three of its flags |
| 8 | You found the field touched only in `session_slow_path` |

**Criterion 3 is the one that catches people.** A `uint64_t` at `+0x08` and two `uint32_t`s at `+0x08`
and `+0x0c` produce identical machine code for everything except a load of the whole thing. If no
function ever loads all eight bytes at once, you cannot distinguish them statically at all — and both
readings decompile plausibly. This is the canonical example of a recovered structure being *internally
consistent and wrong*.

Here it happens to be resolvable, because `session_init` stores a 64-bit argument with `str x`.
**Note which single instruction settled it.** On a real target that instruction may not exist, and the
honest answer is "8 bytes at `+0x08`, subdivision unknown".

---

## 6. Confirm it at run time

A recovered structure is a hypothesis. Chapter 68's evidence ladder puts an unconfirmed layout at
Tier 3 and a layout confirmed by observation at Tier 5, and the difference is one Frida script.

### 6.1 Journal entry

Before running anything, write:

- **H:** the layout in section 4 is correct.
- **P:** printing each field at the exit of `session_seal` will show a magic of `0x5345534e`, a
  readable ASCII user name, a small integer state, and a plausible timestamp.
- **R:** any field that prints as garbage falsifies that field's offset or width.

### 6.2 The script

```javascript
// Frida REPL -- confirm a recovered structure by printing every field.
// frida -U -f <package> -l confirm-struct.js --no-pause
const LIB = "libsession.so";
const IMAGEBASE = 0x0;              // from idaapi.get_imagebase(); do NOT assume
const SEAL_EA   = 0x508c;           // session_seal, from your own analysis

const m = Process.findModuleByName(LIB);
if (m === null) { throw new Error(LIB + " is not loaded -- check /proc/<pid>/maps"); }
const at = (ea) => m.base.add(ptr(ea).sub(IMAGEBASE));

function dumpCtx(s, tag) {
    console.log("--- " + tag + "  ctx=" + s);
    console.log("  +0x00 magic      = 0x" + s.readU32().toString(16));
    console.log("  +0x04 flags      = 0x" + s.add(0x04).readU32().toString(16));
    console.log("  +0x08 issued_at  = "   + s.add(0x08).readU64());
    console.log("  +0x10 key        =\n" + hexdump(s.add(0x10), { length: 16, header: false, ansi: false }));
    console.log("  +0x20 user       = '" + s.add(0x20).readUtf8String() + "'");
    console.log("  +0x40 crc        = 0x" + s.add(0x40).readU32().toString(16));
    console.log("  +0x44 state      = "   + s.add(0x44).readS32());
    console.log("  +0x48 step_count = "   + s.add(0x48).readU32());
    console.log("  +0x4c reserved   = "   + s.add(0x4c).readU32());
}

Interceptor.attach(at(SEAL_EA), {
    onEnter(args) { this.s = args[0]; dumpCtx(this.s, "seal ENTER"); },
    onLeave(rv)   { dumpCtx(this.s, "seal LEAVE  rv=" + rv.toInt32()); }
});
```

### 6.3 Reading the result

| Observation | Verdict |
|---|---|
| `magic = 0x5345534e` | `+0x00` confirmed: 4 bytes, and you have the value |
| `user` prints readable text | `+0x20` confirmed as a NUL-terminated string |
| `state` changes 0 → 1 → 2 across the session | `+0x44` confirmed as the enum |
| `issued_at` is a plausible epoch-like value | `+0x08` confirmed as one 8-byte field |
| `step_count` increments by exactly 1 per call | `+0x48` confirmed as the counter |
| Any field is garbage or wildly implausible | **That field is wrong.** Fix the offset or the width and re-run |

> **⚠️ Warning**
> A garbage value is a *refutation*, and it is the useful outcome. A run in which everything looks
> plausible confirms the layout. A run in which one field is nonsense tells you exactly which
> assumption to revisit — which is more information. Chapter 68 §3.5 calls this choosing the cheapest
> decisive experiment; this one costs three minutes.

### 6.4 If you have no device

You are not blocked. Build a small host-side driver instead:

```bash
# host — build a runner for the same source, for your own machine
cd /tmp && cat > drive.c <<'EOF'
#include <stdio.h>
#include <string.h>
extern int session_init(void *, const char *, unsigned long long);
extern int session_dispatch(void *, int);
extern int session_seal(void *);
int main(void) {
    unsigned char s[0x50];
    memset(s, 0xAA, sizeof s);            /* poison, so untouched bytes show */
    session_init(s, "tester", 1700000000ULL);
    session_dispatch(s, 0);
    session_seal(s);
    for (unsigned i = 0; i < sizeof s; i++)
        printf("%02x%s", s[i], (i % 16 == 15) ? "\n" : " ");
    return 0;
}
EOF
```

Compile it for your host against a host build of the same sources, and read the hex dump directly.
Poisoning the buffer with `0xAA` first is the trick worth keeping: **any byte still `0xAA` after
initialisation is padding, or a field nothing writes.** That is a direct measurement of the holes in
the layout, and it is exactly what section 7 is about.

---

## 7. Now break it

This is the half that transfers to real targets.

The fixture's structure has **no padding at all**, which is a small lie about real code. Genuine
structures acquire holes wherever a field's alignment forces one, and a hole is the single most common
reason a recovered structure ends up one field short or every subsequent offset wrong.

### 7.1 Introduce a hole

Edit [`../examples/01-session-target.c`](../examples/01-session-target.c) and change the structure:

```c
typedef struct {
    uint32_t magic;
    uint8_t  version;      /* <-- NEW: one byte, at +0x04 */
    uint32_t flags;        /* now forced to +0x08 by alignment */
    uint64_t issued_at;
    uint8_t  key[16];
    char     user[32];
    uint32_t crc;
    int32_t  state;
    uint32_t step_count;
    uint32_t reserved;
} session_ctx;
```

Add one use of the new field so the compiler cannot ignore it — for example, set
`s->version = 1;` in `session_init` and check it in `session_seal`.

Rebuild:

```bash
# host
OUTDIR=/tmp/ch58-v2 ./build.sh
```

### 7.2 Predict before you look

**Journal entry.** Write down, before disassembling:

1. What is `sizeof` now?
2. At what offset is `flags`?
3. How many padding bytes are there, and where?
4. Which offsets in your original table are now wrong?

### 7.3 Re-derive

```bash
# host
"$NDKBIN/llvm-objdump" -d --disassemble-symbols=session_init /tmp/ch58-v2/libsession-unstripped.so
```

Compare against your predictions. Then check the `memset` size against your answer to question 1.

**What you should find:** `version` occupies one byte at `+0x04`, and `flags` — a `uint32_t` requiring
4-byte alignment — cannot start at `+0x05`, so the compiler inserts **three padding bytes** and places
it at `+0x08`. Everything after it shifts by 8.

**What is instructive about it:** the three padding bytes are *never touched by any instruction*. They
are invisible in the disassembly. A recovery that reads only the accesses will produce a structure
with `version` at `+0x04` and `flags` at `+0x08` and **no record of what is between them** — which is
correct about behaviour and silent about layout.

### 7.4 The rule that comes out of this

> **🧠 Mental Model**
> **Alignment padding is invisible to access-based recovery**, because nothing accesses it. The
> consequence: a recovered structure's *field positions* can be right while its *field list* is
> incomplete. When your recovered layout has a gap you cannot account for, the first hypothesis is
> not "there is a hidden field" — it is "there is padding, because a wider field follows a narrower
> one".
>
> And the corollary that catches people the other way: **a recovered structure with no gaps at all is
> slightly suspicious**, because real structures usually have some. If you have derived a perfectly
> dense layout, either the original was carefully packed — which is common in serialisation code and
> rare elsewhere — or you have merged two fields into one.

---

## 8. Success criteria

| # | Criterion |
|---|---|
| 1 | You derived the original nine-field layout from the listing, without the answer key |
| 2 | You got `sizeof` from `memset`, not by rounding up the largest offset |
| 3 | You can state which single instruction proved `+0x08` is one field and not two |
| 4 | You wrote the structure as compilable C |
| 5 | You confirmed it at run time (device or host driver) and every field was plausible |
| 6 | You can name what a garbage field would have meant |
| 7 | You predicted the new layout **before** rebuilding, and were right about `flags` moving to `+0x08` |
| 8 | You can explain why the three padding bytes are invisible in the disassembly |
| 9 | You wrote one sentence on when a dense recovered structure should make you suspicious |

---

## 9. Going further

| Variation | What it teaches |
|---|---|
| Add `__attribute__((packed))` to the structure and rebuild | Every field moves; unaligned accesses appear; on some architectures the code gets much worse. Packed structures are common in wire formats |
| Add a nested structure as a field | Recovery finds a *flat* offset list; the nesting is a modelling choice you make, not something in the binary |
| Add a `union` | Two fields at the same offset with different widths. The disassembly shows both accesses and cannot tell you they are exclusive |
| Add a pointer field and look at `.data.rel.ro` | Chapter §3.5's relocation point, in the structure context |
| Build for `armeabi-v7a` and compare | Different pointer size, so every offset after the first pointer changes. **This is why analysing the wrong ABI is not a small mistake** |

That last row is worth doing once. Chapter 68 measured a session correlating an API 35 emulator's
runtime against an API 30 phone's static corpus and calls it the worst kind of error, because
everything stays internally consistent. A structure recovered from the `armeabi-v7a` build and applied
to the `arm64-v8a` one behaves exactly like that: plausible, consistent, wrong.

---

## 10. What to carry forward

- **Three rules do all the work**: the instruction names the width, a loop bound gives an array
  length, `memset` gives `sizeof`.
- **A recovered structure is a hypothesis.** Print every field at run time; one garbage field means
  one wrong offset.
- **A `uint64_t` and two adjacent `uint32_t`s are indistinguishable** unless something loads all eight
  bytes at once. When nothing does, say "subdivision unknown" rather than guessing.
- **Padding is invisible**, so a recovered layout can be right about positions and incomplete about
  fields.
- **A perfectly dense recovered structure is worth a second look.**
- IDA's *Create new struct type* is a real convenience and it **only sees the current function**.
  Generate from the initialiser.

---

| Next | |
|---|---|
| [Lab 03 — FLIRT and type libraries](lab-03-flirt-and-typelibs.md) | Naming the code you should not read |
| [Lab 01 — Your first database](lab-01-first-database.md) | If you skipped it, the triage habit is there |
| [57-Ghidra §3.11](../../57-Ghidra/README.md) | The same technique in the free tool, in more depth on the retyping loop |
