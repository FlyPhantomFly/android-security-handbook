# Lab 03 — Break the Verifier on Purpose

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 02](lab-02-patch-and-rebuild.md), [Chapter 14 §3.1–§3.4, §5.5, §7.5](../README.md)
**Needs:** the app from Lab 02 (or any APK you may modify), `apktool`, `smali`/`baksmali`,
`zipalign`, `apksigner`, `adb`, a device or emulator.

---

## Objective

Induce every class of rejection the toolchain can produce, one at a time, read the exact message each
one gives, and fix it. By the end you should be able to look at a failure and say, within seconds,
**which of the three gates rejected you** and **which line caused it**.

The three gates, in the order you meet them:

| Gate | Runs when | Catches | Cost of hitting it |
|---|---|---|---|
| **The assembler** (`smali` / `apktool b`) | On your machine, at build | Register arithmetic, syntax, malformed descriptors, structural impossibilities | Seconds. This is the cheap one |
| **The installer** (`PackageManager`) | At `adb install` | Signature and packaging problems | A minute |
| **The verifier** (ART, at class load) | **When the class is first used on the device** | Type consistency, instruction adjacency, control-flow reachability | Potentially an hour, because it fires late and on one screen only |

Most people never learn the third gate systematically. They meet each rejection once, by accident,
under time pressure, and re-derive the fix each time. This lab replaces that with a catalogue.

## Why this matters

A `VerifyError` does not appear at build. It does not appear at install. It appears when the user
navigates to the screen that touches your edited class — which on a large app might be five taps in,
or might be behind a login you have not got past yet. If you cannot read the rejection you are
debugging blind.

---

## Setup

### A workbench, not a real app

You want a fast edit-assemble cycle. Working through `apktool b` on a whole APK for each experiment
wastes minutes; working on a single class through `smali`/`baksmali` takes seconds.

```bash
# host
mkdir -p lab03 && cd lab03
```

Create `Lab03.smali` by hand:

```smali
.class public Lcom/example/vault/Lab03;
.super Ljava/lang/Object;

.method public static ok(Ljava/lang/String;)Z
    .locals 1
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    return v0
.end method
```

Then:

```bash
# host -- the fast loop. Under a second.
smali a Lab03.smali -o out.dex --api 34 && echo "ASSEMBLER: OK"
```

Every experiment below is: edit `Lab03.smali`, run that command, read what happens. When the
assembler *accepts* something the verifier will reject, you take the extra step of putting the class
into the app and running it.

### Getting a class onto the device for the verifier experiments

```bash
# host -- from the Lab 02 project directory
cp Lab03.smali work/smali/com/example/vault/Lab03.smali
```

Then add one line to `MainActivity`'s `onCreate` so the class is actually loaded — the verifier only
runs when a class is used:

```java
Log.i(TAG, "lab03 -> " + Lab03.ok("x"));
```

and rebuild through the usual pipeline. **A class that is never referenced is never verified**, which
is itself worth internalising: an unreachable broken method in an APK causes no symptom at all.

### The pre-flight check

```bash
# host
python3 ../scripts/smali_frame.py Lab03.smali --check
```

Run this before every assemble. Part of the point of this lab is to learn what the tool catches
(hazards 1–5 in its header) and what only the real verifier catches.

---

## Part A — Assembler rejections

These never reach the device. They are the cheap failures and you want to be able to recognise them
instantly so you do not go looking for a verifier problem.

### A1 — A register that does not exist

```smali
.method public static a1()I
    .locals 2
    const/4 v0, 0x1
    const/4 v5, 0x2
    add-int v0, v0, v5
    return v0
.end method
```

```bash
# host
smali a Lab03.smali -o out.dex --api 34
```

**Observe.** The assembler names the register and the line.

**Diagnose.** `.locals 2` on a static method with no parameters gives a frame of exactly `v0` and
`v1`. `v5` is outside it.

**Fix.** `.locals 6`. Or better, use `v1`, which already exists.

**Pre-flight catches it:**

```text
[ASSEMBLE] line N   a1()I
           v5 resolves to v5 but registers_size is 2. Raise .locals.
```

### A2 — Above the 16-register wall

```smali
.method public static a2(I)I
    .registers 20
    const/4 v16, 0x1
    move v17, v16
    add-int/2addr v17, v16
    return v17
.end method
```

**Observe.** The assembler rejects it even though `v16` and `v17` are well inside a 20-register frame.

**Diagnose.** `const/4` is format `11n` — its register field is **4 bits**, so it can only name
`v0`–`v15`. Same for `move` (`12x`) and `add-int/2addr` (`12x`). The frame is big enough; the
*instruction encoding* is not.

**Fix**, in order of preference:

1. Use a low register that is dead at that point.
2. Use the wider variant: `const/16 v16, 0x1` (format `21s`, 8-bit register field);
   `move/from16 v17, v16` (`22x`).
3. Marshal down and back: `move/16 v0, v16`, operate on `v0`, `move/16 v16, v0`.

**Q1.** Which of these three is preferable when you are patching a method you did not write, and why?

<details>
<summary>Answer</summary>

(1), by a wide margin. Reusing a dead low register changes nothing about the frame, so nothing else in
the method moves. (2) is fine but only some instructions have a wider variant. (3) always works and
costs the most instructions — reach for it last.

To find a dead low register, look for a `vN` (N ≤ 15) that is written before your insertion point and
not read after it. `baksmali --no-parameter-registers` makes this easier to see, because it stops
hiding parameter registers behind `p` names.

</details>

### A3 — A malformed descriptor

```smali
.method public static a3(Ljava/lang/String)Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
```

**Observe.** A parse error.

**Diagnose.** `Ljava/lang/String` is missing its terminating `;`. The semicolon is **part of the
descriptor**, not a separator.

**Q2.** Write out the descriptor for `boolean f(String s, int[] a, long n)` and then say how many
parameters `(Ljava/lang/String;[IJ)Z` has.

<details>
<summary>Answer</summary>

`(Ljava/lang/String;[IJ)Z`. Three parameters. There are no separators between parameter descriptors
— the `;` after `String` terminates *that* descriptor. You read a descriptor by walking it one
descriptor at a time: `L…;` consumes up to the semicolon, `[` prefixes the next one, and single
letters stand alone.

</details>

### A4 — Package separators

```smali
    invoke-static {v0}, Ljava.lang.Integer;->parseInt(Ljava.lang.String;)I
```

**Observe.** Depending on the assembler version this either fails to parse or assembles into a
reference to a class that does not exist, and then fails at runtime with
`NoClassDefFoundError`/`NoSuchMethodError`.

**Diagnose.** Package separators in a type descriptor are `/`, never `.`. The `.` form is the Java
source spelling and the `L…;` form is the DEX spelling.

**Q3.** Why is it dangerous that some versions accept this silently?

<details>
<summary>Answer</summary>

Because the failure moves from build time to run time, and changes category: instead of an assembler
error naming your line, you get a `NoClassDefFoundError` in `logcat` on some screen, which looks like
a missing dependency rather than a typo. Failures that move later are always more expensive.

</details>

### A5 — An empty `try` range

```smali
.method public static a5(Ljava/lang/String;)I
    .locals 2
    :try_start_0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    const/4 v0, 0x0
    return v0
    :catch_0
    move-exception v1
    const/4 v0, -0x1
    return v0
.end method
```

**Observe.** Rejected — a `try_item` covering zero instructions is invalid.

**Diagnose.** You deleted the whole body of a protected region. Very easy to do when you are gutting
a method that happened to sit inside a `try`.

**Fix.** Put a `nop` between the labels. It is one code unit and it does nothing, which is exactly
what you want.

---

## Part B — Verifier rejections

These assemble cleanly, install cleanly, and fail at class load. Each one below must be taken all the
way onto the device.

### The instrumentation you need first

```bash
# host
adb logcat -c
adb logcat -s art:* AndroidRuntime:* System.err:*
```

Leave that running in a second terminal for all of Part B.

### B1 — `move-result` adjacency

```smali
.method public static b1(Ljava/lang/String;)Z
    .locals 3
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    const-string v1, "oops"
    move-result v0
    return v0
.end method
```

**Observe.** Assembles. Installs. Fails at class load.

**Diagnose.** `move-result*` must **immediately** follow the `invoke-*` whose value it collects. The
return value lives in a transient slot valid only at that instant. There is a second, quieter bug
here too: even if it were legal, `move-result v0` would now be collecting nothing meaningful.

**Fix.** Move `const-string v1, "oops"` above the invoke, or below the `move-result`.

**Pre-flight catches it:**

```text
[VERIFY  ] line N   b1(Ljava/lang/String;)Z
           move-result does not immediately follow an invoke (previous instruction
           is 'const-string'). This is a VerifyError at class load.
```

**Q4.** You want to log a method's argument *and* its return value. Where do the two log calls go?

<details>
<summary>Answer</summary>

The argument log goes **before** the `invoke`. The return-value log goes **after** the
`move-result*`. Nothing whatsoever goes between them. If you want both in one place, capture the
argument into a spare register before the invoke and log both after the `move-result`.

</details>

### B2 — `move-exception` position

```smali
.method public static b2(Ljava/lang/String;)I
    .locals 3
    :try_start_0
    invoke-static {p0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I
    move-result v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0
    return v0

    :catch_0
    const-string v2, "caught"
    move-exception v1
    const/4 v0, -0x1
    return v0
.end method
```

**Observe.** Assembles; fails at class load.

**Diagnose.** `move-exception` is legal **only** as the first instruction of a handler. This is the
exception-handling twin of B1: the exception object is handed over in a slot valid only at handler
entry.

**Fix.** Put `move-exception v1` first, then the `const-string`.

**Q5.** A handler that ignores the exception entirely — no `move-exception` at all — is that legal?

<details>
<summary>Answer</summary>

Yes. `move-exception` is how you *collect* the exception object; a handler that does not want it
simply omits the instruction. What is illegal is having it anywhere other than first.

</details>

### B3 — Wrong instruction family for the type

Three variants. Try each.

```smali
# B3a -- return-object on an int
.method public static b3a()I
    .locals 1
    const/4 v0, 0x1
    return-object v0
.end method

# B3b -- return on a reference
.method public static b3b()Ljava/lang/String;
    .locals 1
    const-string v0, "x"
    return v0
.end method

# B3c -- iget on a boolean field
#   iget v0, p0, Lcom/example/vault/Lab03;->flag:Z    (should be iget-boolean)
```

**Observe.** All three assemble and all three fail verification.

**Diagnose.** **Registers are untyped; opcodes are typed.** The instruction is where the type
information lives, and the verifier computes what each register holds at each point by propagating
those declarations. Three disagreements are possible and all are fatal: instruction versus register
content, instruction versus method descriptor, instruction versus field descriptor.

**The rule to memorise:**

| Descriptor | Return instruction | Field/array accessor suffix |
|---|---|---|
| `V` | `return-void` | — |
| `Z` | `return` | `-boolean` |
| `B` | `return` | `-byte` |
| `S` | `return` | `-short` |
| `C` | `return` | `-char` |
| `I` | `return` | *(none)* |
| `F` | `return` | *(none)* |
| `J` | `return-wide` | `-wide` |
| `D` | `return-wide` | `-wide` |
| `L…;` / `[…` | `return-object` | `-object` |

**Q6.** `null` is `const/4 v0, 0x0`, and `false` is also `const/4 v0, 0x0`. The bytes are identical.
How does the verifier tell them apart?

<details>
<summary>Answer</summary>

It does not need to, at the point of the `const/4`. A zero-valued register is in a state the verifier
tracks as "could be the integer zero or could be a null reference". What resolves it is the **next
instruction that uses it**: `return-object` declares it a reference, `return` on a `Z`-returning
method declares it a boolean. If the two uses on different control-flow paths disagree, *that* is the
error. This is why the type lives in the opcode and not in the data.

</details>

### B4 — Wide-value mistakes

```smali
# B4a -- reading half of a long
.method public static b4a(J)I
    .locals 2
    move v0, p1        # p1 is the HIGH half of the long
    return v0
.end method

# B4b -- a wide value straddling the end of the frame
.method public static b4b()J
    .locals 1
    const-wide/16 v0, 0x1     # needs v0 AND v1; only v0 exists
    return-wide v0
.end method

# B4c -- clobbering the high half
.method public static b4c(J)J
    .locals 3
    const/4 v0, 0x5
    move-wide v1, p0          # v1:v2
    const/4 v2, 0x7           # destroys the high half of v1:v2
    return-wide v1
.end method
```

**Observe.** B4b is caught by the assembler. B4a and B4c reach the verifier.

**Diagnose.** A 64-bit value occupies two adjacent registers and the verifier tracks the pair as a
unit. Touching the high half alone, or writing a 32-bit value over it, breaks the pair.

**Q7.** For `static void f(long a, int b)` with `.registers 4`, write out the `p`-to-`v` map.

<details>
<summary>Answer</summary>

`ins_size` = 2 (`long`) + 1 (`int`) = 3. `first_param_reg` = 4 − 3 = 1.

```text
    p0 == v1   'a', LOW half      the long occupies v1:v2
    p1 == v2   'a', high half
    p2 == v3   'b'
    v0         the only free local
```

`b` is `p2`. Anyone who said `p1` counted commas instead of words.

</details>

### B5 — Escaping an uninitialised reference

```smali
.method public static b5()Ljava/lang/StringBuilder;
    .locals 1
    new-instance v0, Ljava/lang/StringBuilder;
    return-object v0
.end method
```

**Observe.** Assembles; fails verification.

**Diagnose.** `new-instance` allocates but does **not** run the constructor. Between it and the
`invoke-direct … <init>` the register holds an *uninitialised reference*, a state the verifier tracks
precisely. In that state the value may not be returned, stored in a field, or passed anywhere.

**Fix.**

```smali
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    return-object v0
```

**Q8.** Why does this rule matter for patching, in practice?

<details>
<summary>Answer</summary>

Because it means **you cannot insert anything between `new-instance` and its `invoke-direct`** — no
logging, no register shuffling, nothing that touches the new object. If you need to log around an
object construction, do it before the `new-instance` or after the `<init>` call. This is the third
adjacency rule, alongside `move-result` and `move-exception`, and it catches people who have learned
the other two.

</details>

### B6 — Falling through into a payload

```smali
.method public static b6()[I
    .locals 2
    const/4 v0, 0x2
    new-array v0, v0, [I
    fill-array-data v0, :array_0

    :array_0
    .array-data 4
        0x1
        0x2
    .end array-data
.end method
```

**Observe.** Rejected.

**Diagnose.** Two problems. The method has no `return`, and execution would run straight off the
`fill-array-data` into the payload — which is **data**, not code. The instruction immediately before
a payload label must be an unconditional transfer: `return*`, `goto` or `throw`.

**Fix.**

```smali
    fill-array-data v0, :array_0
    return-object v0

    nop

    :array_0
    .array-data 4
        0x1
        0x2
    .end array-data
```

The `nop` is 4-byte alignment padding for the payload. Leave it alone.

### B7 — Unbalanced monitors

```smali
.method public b7()V
    .locals 2
    iget-object v0, p0, Lcom/example/vault/Lab03;->lock:Ljava/lang/Object;
    monitor-enter v0
    return-void
.end method
```

**Observe.** Rejected on some versions; on others it verifies and produces a lock that is never
released.

**Diagnose.** Monitors must be balanced on **every** path out of the method, including exception
paths. That is why a `synchronized` block compiles to `monitor-enter` / body / `monitor-exit` **plus**
a `catchall` handler that also does `monitor-exit` before rethrowing.

**Q9.** You are deleting a chunk of code from inside a `synchronized` block. What must you check?

<details>
<summary>Answer</summary>

That you have not removed a `monitor-exit`, and that the `catchall` handler is still intact. The
failure mode when this slips through is not a crash — it is an app that hangs, sometimes much later,
with no error anywhere. That is far harder to diagnose than a `VerifyError`, so check before you
delete.

</details>

---

## Part C — Failures that are neither

Two rejections people mistake for verifier problems.

### C1 — `NoSuchMethodError`

```smali
    invoke-virtual {p0, v0}, Ljava/lang/String;->equalsIgnoreCasE(Ljava/lang/String;)Z
```

Assembles. Installs. Verifies. Throws `NoSuchMethodError` **when that line executes**.

**Diagnose.** Method references are resolved lazily. The verifier checks the *shape* of the
instruction, not that the target exists. A typo in a method name or a wrong descriptor — a missing
parameter, `Ljava/lang/Object;` where `Ljava/lang/String;` was required — survives everything until
the instruction runs.

**Q10.** Why is this failure mode worse than a `VerifyError`?

<details>
<summary>Answer</summary>

Because it fires per-instruction rather than per-class. A `VerifyError` kills the class the first time
it is loaded, so you find it as soon as the screen opens. A `NoSuchMethodError` fires only on the
path that reaches your line, which might be a rare branch — so your patch can appear to work for an
hour and then crash on an edge case. Always check descriptors character by character against a
`baksmali` listing of the real method.

</details>

### C2 — Verified fine, behaviour silently wrong

This is the worst outcome and no gate catches it.

```smali
# Original:  .registers 6, ins_size 3, so p0 == v3
.method public check(Ljava/lang/String;I)Z
    .registers 6
    iget-object v0, v3, Lcom/example/vault/Lab03;->name:Ljava/lang/String;
    ...
.end method

# You raise it to make room for a local:
.method public check(Ljava/lang/String;I)Z
    .registers 7
    iget-object v0, v3, Lcom/example/vault/Lab03;->name:Ljava/lang/String;   # v3 is now a LOCAL
    ...
.end method
```

**Observe.** It assembles. It installs. It verifies. It does the wrong thing.

**Diagnose.** Raising `.registers` moved `p0` from `v3` to `v4`. The line still says `v3`, which is
now an uninitialised local. Whether this verifies depends on what else writes `v3`; often it does,
because the types happen to line up.

**This is why the pre-flight tool reports `FRAGILE`:**

```bash
# host
python3 ../scripts/smali_frame.py Lab03.smali --check
```

```text
[FRAGILE ] line N   check(Ljava/lang/String;I)Z
           raw v3 is parameter p0. Correct today, but raising .registers moves
           the parameters and this reference will not move with them.
           Write p0 instead.
```

**The three habits that prevent it:**

1. Use `.locals`, not `.registers`, in anything you edit.
2. Refer to parameters by `pN`, always.
3. Before raising a frame, run `--check` and rewrite every `FRAGILE` line to its `pN` form **first**.

---

## Part D — The catalogue

Fill this in from your own runs. This is the deliverable — a page you can look at when something
fails at 2am.

| # | What you did | Which gate | Exact message (first line) | Fix |
|---|---|---|---|---|
| A1 | register ≥ `registers_size` | assembler | | `.locals` up |
| A2 | register > `v15` in a 4-bit field | assembler | | low register / wider variant |
| A3 | missing `;` in a descriptor | assembler | | add it |
| A4 | `.` instead of `/` | assembler or runtime | | use `/` |
| A5 | empty `try` range | assembler | | insert `nop` |
| B1 | split `invoke` from `move-result` | verifier | | move the insertion |
| B2 | `move-exception` not first | verifier | | put it first |
| B3 | wrong return/accessor family | verifier | | match the descriptor |
| B4 | wide-pair damage | assembler or verifier | | count words |
| B5 | uninitialised reference escaped | verifier | | call `<init>` first |
| B6 | fall-through into a payload | verifier | | `return`/`goto` before it |
| B7 | unbalanced monitor | verifier or hang | | balance every path |
| C1 | bad method reference | runtime | | check the descriptor |
| C2 | raised `.registers`, raw `vN` left | **none** | *(silence)* | use `pN` and `.locals` |

---

## Success criteria

- [ ] You produced all fourteen failures and recorded the real message for each.
- [ ] You can name which gate catches which, without looking.
- [ ] You can state the three adjacency rules — `move-result`, `move-exception`, `new-instance`/`<init>` — from memory.
- [ ] You can explain why C2 is worse than every `VerifyError` above it.
- [ ] You ran `smali_frame.py --check` before each assemble and know what it does and does not catch.
- [ ] You can recite the descriptor-to-instruction-family table.

## A closing note on the verifier

Everything in Part B is the verifier doing its job correctly. It is worth being explicit about what
that job **is**: it proves the bytecode is internally type-consistent so the compiler can omit runtime
checks and generate faster code. It is a **correctness** mechanism.

It is **not** a sandbox. It says nothing about what the app is permitted to do, and it is bypassed
entirely the moment the app calls into its own `.so`. Treat a passing verification as "this bytecode
is well-formed", never as "this bytecode is safe". [12 §3.29](../../12-DEX-Internals/README.md) and
[13 §2.5](../../13-ART/README.md) both make the same point from different directions.

## Next

[Lab 04 — CTF: The Latin VM](lab-04-ctf-the-latin-vm.md) is the final lab: an app whose flag check
runs inside a virtual machine that the app itself implements, in Smali. You will have to read the
interpreter to learn its instruction set, then reverse the program it runs.
