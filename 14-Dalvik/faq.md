# 14 — Dalvik and Smali · FAQ

Real questions, including the ones people are embarrassed to ask. Answered directly, with a pointer
into [README.md](README.md) for the full treatment.

---

### 1. Why am I learning a dead virtual machine?

You are not. You are learning an **instruction set and its notation**, both of which are completely
alive.

The Dalvik *virtual machine* — the `libdvm.so` interpreter, `dexopt`, the trace JIT — was removed from
Android after 4.4 and no shipping device has run it since 2014. But the **bytecode** it was built to
execute is still exactly what `d8` emits from your Kotlin today, and ART executes exactly that
instruction set. `baksmali` renders it, you patch it, and the format's name is still "Dalvik
Executable".

The chapter covers the dead VM for two reasons: its design decisions are still binding constraints
(the register model, the 16-register wall, `move-result` adjacency), and "why does Android bytecode
look like this" is a question with a real answer that only the history provides.

*(README §1, §3.21, §3.22)*

---

### 2. Why are there two names for the same register, `v0` and `p0`?

Because parameters live at the **top** of the frame, not the bottom, and their register numbers depend
on the frame's total size.

A method's registers are one flat array. The **last** `ins_size` of them hold the incoming arguments.
So for a method with `.registers 6` and three incoming words, the arguments are in `v3`, `v4`, `v5`.
Writing that as `p0`, `p1`, `p2` is a convenience: it means "argument 0" regardless of what the total
frame size happens to be.

```text
    pN  ==  v(registers_size - ins_size + N)
```

Both spellings assemble to **identical bytes**. `iget-object v0, v3, …` and `iget-object v0, p0, …`
are the same instruction.

Why at the top? Because it makes calls free. The caller lays its outgoing arguments out in a
contiguous window at the top of its own frame, and the callee's frame is arranged so that window *is*
its parameter registers. No copying.

*(README §2.4, §3.2)*

---

### 3. Why does `invoke-virtual` list its registers in braces?

Because it is a **list with a count**, and the count is encoded in the instruction.

`invoke-virtual {v1, v2}, Lcom/example/A;->f(I)V` is not addressing a range or a set. It is saying
"there are two argument registers, and they are `v1` and `v2`, in that order". The `35c` instruction
format has a 4-bit field for the count and up to five 4-bit register fields.

For an **instance** method the first register in the braces is the receiver — `this` — and the rest are
the declared parameters. For a `static` method there is no receiver, so `{}` with no registers at all
is a perfectly normal, valid instruction.

Two rules people trip over:

- A `long` or `double` argument takes **two consecutive entries**: `{v2, v3}` for one `long`.
- The maximum is **five words**, not five parameters.

*(README §3.10.11)*

---

### 4. What is `/range` for?

The `35c` invoke format packs each register number into 4 bits, so it can only name `v0`–`v15`, and
there is only room for five of them. Two limits, one instruction format.

`/range` is the escape hatch. `invoke-virtual/range {v20 .. v26}` encodes a **first register** (16
bits, so up to `v65535`) and a **count** (8 bits, so up to 255 arguments). The trade-off is that the
arguments must **already be in consecutive registers, in order**.

That last clause is why converting a `35c` call to a `3rc` call is not a text edit. If you write a
`/range` call by hand you must first emit `move` instructions to marshal the values into a contiguous
run.

Other `/range` instructions — `filled-new-array/range`, `invoke-custom/range` — work the same way.

*(README §3.4, §3.10.11)*

---

### 5. My edited Smali fails to rebuild. Why?

`apktool b` / `smali a` failures fall into a small number of buckets:

| Error message mentions | Cause | Fix |
|---|---|---|
| A register number, "invalid register", "out of range" | You used `vN` where `N >= registers_size`, or a 4-bit field cannot hold your register number | Raise `.locals`, or move the value into a low register first, or use the `/from16` variant |
| "cannot find" a label | You referenced a label that does not exist, or deleted it | Check spelling; labels are case-sensitive |
| A type or method not found | A malformed descriptor — a missing `;`, a `.` instead of `/`, a wrong parameter list | Read the descriptor character by character. `(Ljava/lang/String;I)V`, not `(Ljava/lang/String,I)V` |
| "mismatched input" at a line | A syntax error — usually a missing comma, a stray character, or an instruction that does not exist | Compare against a `baksmali` listing of a similar instruction |
| An empty `try` block | You deleted the whole body of a protected range | Put a `nop` inside it |
| Nothing about Smali at all, complains about resources | The failure is in resource re-encoding, not your edit | Re-decode with `apktool d -r`, patch, and rebuild — `-r` avoids the resource round trip entirely |

And the failure that is *not* a rebuild failure: if it builds and installs and then the app crashes on
one screen, that is the **verifier**, not the assembler. See question 6.

*(README §7.5, §5.5)*

---

### 6. It built and installed, then crashed when I opened one screen. What happened?

The ART **bytecode verifier** rejected the class, and verification happens at **class load**, not at
install. So the app starts fine and dies the moment something touches the class you edited.

```bash
# host
adb logcat -c && adb logcat -s art:* AndroidRuntime:*
```

The rejection names the class, the method and usually an instruction offset. The usual causes, in
frequency order:

1. You inserted an instruction between an `invoke-*` and its `move-result`.
2. You raised `.registers` and the body still refers to a parameter by its old raw `vN`.
3. You used the wrong instruction family for the type — `return` where `return-object` was needed,
   `iget` on a `Z` field.
4. You put an instruction above a `move-exception` at the top of a catch handler.
5. You inserted code between `new-instance` and its `invoke-direct <init>`.

*(README §5.5, §7.5)*

---

### 7. What is the difference between `.registers` and `.locals`, and which should I use?

`.registers N` declares the **total** frame size, parameters included. `.locals N` declares only the
extra registers beyond the parameters, and lets the assembler compute the total.

`baksmali` always emits `.registers`. When you are **editing**, prefer `.locals`, because adding a
local becomes a one-character change with no knock-on effects.

The danger with `.registers` is specific and worth spelling out. Suppose a method is `.registers 6`
with three incoming words, so `p0 == v3`. You raise it to `.registers 7` to make room for a new local.
Now `p0 == v4` — but every line in the body that says `v3` still says `v3`, and `v3` is now a local
holding garbage. The method may still verify, because the types can happen to line up, and it will
behave wrongly with no error.

The safe habits: use `p` names for parameters, use `.locals`, and never mix the two directives in one
method.

*(README §3.2)*

---

### 8. `if-eqz v0, :cond_5` — does that mean "if v0 is true"?

No. It means **"if `v0` is zero, jump to `:cond_5`"**. The condition on the instruction is the
condition under which the branch is **taken**.

This inverts constantly relative to Java source, because `if (x) { A } else { B }` compiles to:

```smali
    if-eqz vX, :else     # if x is FALSE, jump to the else block
    # A -- the "true" body is the fall-through
    goto :end
    :else
    # B
    :end
```

So the code immediately after an `if-eqz` is the **non-zero / true** path. Read it twice before you
invert anything.

The `*z` forms also serve as null checks: on an object register, `if-eqz` means "if null". A
`boolean` is an `int` that is 0 or 1, so on a boolean it means "if false".

*(README §3.10.7)*

---

### 9. Why are there seven different `iget` instructions?

Because **registers are untyped and opcodes are typed**.

There is no bit anywhere recording that `v3` currently holds a `String`. The instruction is where the
type lives. `iget-object` says "this field is a reference"; `iget-boolean` says "this field is a
`Z`"; `iget-byte` says "sign-extend an 8-bit value into 32 bits". The verifier uses the opcode to
compute what each register holds at each point, statically, before the class runs.

The same reasoning produces three `return` instructions, three `move` instructions, seven `aget`s,
seven `sget`s, and so on. It looks like bloat and it is actually the whole basis of the type system.

Practical consequence: if you patch a method to return a `String` you need `const-string` +
`return-object`, not `const/4` + `return`. Using the wrong family is a `VerifyError`.

*(README §3.1)*

---

### 10. Where is the `default` case of my `switch`?

There isn't one, in the payload. **Neither `packed-switch` nor `sparse-switch` encodes a default
target.** If the value matches no case, execution continues at the **next instruction after the
switch**.

That is why the default body appears immediately after the switch instruction, which reads oddly the
first time. It is also why a Java `switch` with no `default` produces Smali where the code after the
switch is both the default *and* the join point that every case falls through to.

*(README §3.13)*

---

### 11. Why does my `finally` block appear twice in the Smali?

Because there are no `finally` instructions. The compiler implements it by **duplicating the
`finally` body** onto every exit path: once inline on the normal path, and once inside a `.catchall`
handler that rethrows.

With several exit paths — a `return` in the middle of the `try`, a `break`, several `catch` clauses —
you can see the same body three or four times. This is normal compiler output and is not obfuscation.

*(README §3.12)*

---

### 12. What is `/2addr`, and does it mean the source mutated a variable?

`/2addr` is a two-operand form where the destination is also the first source:
`add-int/2addr v0, v1` is `v0 = v0 + v1`. It exists purely to save one code unit — two bytes.

It does **not** tell you anything about the source. If the compiler happened to reuse a register, then
`int c = a + b;` can compile to `add-int/2addr v0, v1`, and reading that as "`a += b`" is wrong. Do
not infer source-level intent from an encoding chosen for size.

*(README §3.10.13)*

---

### 13. Why is there no `sub-int/lit8`?

Because it is unnecessary: `x - 5` is `add-int/lit8 vA, vB, -5`. The literal field is signed.

What *is* necessary is the other direction — `5 - x` — because you cannot put a literal in a register
field. That instruction is `rsub-int/lit8`, **r**everse **sub**tract.

And a wart worth knowing: the 16-bit version is spelled `rsub-int`, with **no `/lit16` suffix**, even
though every one of its neighbours has one. That inconsistency has been in the specification since
2008 and both `smali` and the AOSP tables use it.

*(README §3.10.13)*

---

### 14. `baksmali` says the file contains invalid instructions, but the app runs fine. What?

You almost certainly have a DEX extracted from an **Android 8.0–10** device's VDEX, containing
**quickened** instructions.

Quickening rewrites `iget v0, v1, Lcom/A;->x:I` — which needs a name lookup — into `iget-quick v0, v1,
offset@12`, which just reads 12 bytes into the object. It is faster and it is not portable: the
offset is only valid against the exact class layout the optimiser saw. Those instructions occupy
opcodes `0xE3`–`0xF2`, which are otherwise unused.

`baksmali` cannot render them symbolically, so it complains. Two fixes:

- `baksmali d --allow-odex-opcodes …` renders them as-is, which is enough to read but not to rebuild.
- **Unquicken first.** `vdexExtractor` uses the VDEX's own metadata to restore the symbolic form.

Quickening was removed in Android 11, so the problem does not arise from API 30 onwards.

*(README §3.10.15)*

---

### 15. The DEX hash changed after I round-tripped it without editing anything. Is that a bug?

No, and it matters that you know it.

`baksmali` is lossless with respect to **instructions**, not with respect to the whole file. Item
ordering in the data section, debug info, and the layout choices `d8` originally made are all
*regenerated* on reassembly. A round trip of an untouched DEX produces a file that behaves identically
and hashes differently.

Two consequences:

1. **A changed hash is not evidence you changed behaviour.** Do not report it as such.
2. **Establish a baseline.** Round-trip the original *first*, then diff your patched build against
   that baseline. Diffing against the untouched original drowns you in irrelevant differences.

*(README §1.3, §6.3)*

---

### 16. Should I patch Smali or hook with Frida?

Frida to **find**, Smali to **fix**.

Frida wins on iteration speed (seconds, not a rebuild cycle), on reading runtime values, on reacting
to runtime state, and on apps that check their own integrity. It loses when the device is not rooted,
when the app detects Frida, and when you need the change to persist with no tooling.

Smali wins when you need permanence, when the target device has no Frida, and when you need to hand a
client a demonstrable APK. It loses when the app verifies its own signature or DEX hash (your re-sign
breaks it), when the logic is in a `.so`, and when the app is packed so the shipped DEX is a stub.

The mistake to avoid is patching before you have confirmed your hypothesis. Fifteen-minute rebuild
cycles to test a guess is the single largest time sink in this discipline.

*(README §5.2, §7.1)*

---

### 17. Why do I have to uninstall before installing my patched APK?

Because you re-signed it with your own key, and Android identifies an application by
**package name + signing certificate**. A different certificate means a different app as far as the
package manager is concerned, so an in-place update is refused with
`INSTALL_FAILED_UPDATE_INCOMPATIBLE`.

Two knock-on effects people forget:

- The app's data directory is wiped, so any login state or local database is gone.
- Anything that depended on the original signature stops working: `signature`-level permissions,
  Google Play licensing, and any server that pins the app's signing certificate.

That last one is why signature pinning server-side is the correct defence against repackaging, and
why a purely client-side integrity check is not.

*(README §2.7, §5.2)*

---

### 18. Why does `zipalign` have to run before `apksigner` and not after?

Because APK Signature Scheme v2 and later sign a digest of **the whole file**, not of individual ZIP
entries. `zipalign` moves bytes around inside the archive to 4-byte-align uncompressed entries — so
running it after signing changes the bytes the signature covers and invalidates it.

The order is always: `apktool b` → `zipalign` → `apksigner sign` → `apksigner verify`.

(`apksigner` can also do the alignment itself with `--alignment-preserved`/`-v4` options depending on
version, but the explicit three-step order works everywhere and is worth making a habit.)

*(README §5.2)*

---

### 19. What actually happened to Dalvik, and why?

ART replaced it in Android 5.0. Five reasons, in the order they mattered:

1. **Warm-up.** A trace JIT gives you nothing for the first seconds of every launch, and launches are
   what users perceive.
2. **Nothing persisted.** The translation cache died with the process, so every launch re-JITted from
   scratch.
3. **GC.** Non-concurrent, non-compacting mark-and-sweep produced visible jank and unavoidable heap
   fragmentation.
4. **64-bit.** `mterp` was hand-written assembly per architecture, and ARM64 arrived in 2013.
5. **Optimisation ceiling.** A trace JIT cannot inline, and Java without inlining is expensive.

The crucial nuance, and a common interview filter: ART replaced the **virtual machine**, not the
**bytecode**. Every opcode in this chapter is unchanged.

*(README §3.21)*

---

### 20. Why did Froyo's JIT compile *traces* instead of whole methods?

Memory, mostly.

A method JIT has to hold the whole method's intermediate representation in RAM while compiling, and
has to store native code for every path in the method — including the ones that never execute. In 2010
an application's entire heap was capped at 16–24 MB. That was not affordable.

A trace is one linear path — a few dozen instructions — and it compiles in microseconds on a background
thread, so no tiering machinery was needed to hide the compile latency. It also profiles itself for
free: what you record *is* what executed.

The costs were real: no optimisation across branches, expensive trace exits that spilled every live
register, duplicated code where paths merged, essentially no inlining, and — the fatal one — nothing
persisted across process lifetimes.

*(README §2.5, §3.17)*
