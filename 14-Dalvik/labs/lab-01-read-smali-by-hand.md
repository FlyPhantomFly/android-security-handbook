# Lab 01 — Read Smali by Hand

**Difficulty:** Beginner
**Time:** 90–150 minutes
**Prerequisites:** [Chapter 14 §1–§3.9](../README.md), [12 — DEX Internals §3.24–3.26](../../12-DEX-Internals/README.md)
**Needs:** a JDK, Android SDK build-tools (`d8`), `baksmali`. **No device, no emulator, no Gradle
project.**

---

## Objective

Take a Java class you wrote yourself, turn it into Dalvik bytecode, and read every line of the result
without a lookup table. By the end you should be able to:

- Compute a method's register frame — `ins_size`, `first_param_reg`, the `p`-to-`v` map — on paper.
- Point at any line in a `baksmali` listing and say what it does and why the compiler emitted it.
- Recognise a `for` loop, a `try`/`finally`, both kinds of `switch`, a string concatenation and an
  array literal from their bytecode shape alone.
- State, from your own measurements, exactly what the register machine bought and what it cost.

## Why this matters

Everything else in this chapter — patching, hunting for keys, defeating a check — assumes you can
*read*. Most people skip this step, learn three patch recipes, and then stall the first time an app
does something the recipes do not cover. An afternoon spent here is the difference between applying
patterns and understanding code.

The second reason is that you control the input. When you disassemble a stranger's APK you cannot
tell whether a strange shape is the compiler, an obfuscator, or your own misreading. Here you wrote
the source, so every surprise has an explanation you can chase down.

---

## Setup

### Step 0 — Confirm your tools

```bash
# host
java -version                  # any JDK 8 or later
javac -version
d8 --version                   # from Android SDK build-tools; add it to PATH
baksmali -version              # from https://github.com/google/smali
```

If `d8` is not on your `PATH`, it lives at
`$ANDROID_HOME/build-tools/<version>/d8` (a shell script wrapping `d8.jar`). On Windows use
`d8.bat`. If you have no SDK at all, download `smali`/`baksmali` and the `r8.jar` release, and invoke
`d8` as `java -cp r8.jar com.android.tools.r8.D8`.

`baksmali` is a jar. If you downloaded `baksmali-x.y.z.jar` rather than installing a wrapper, replace
every `baksmali` below with `java -jar baksmali-x.y.z.jar`.

### Step 1 — Build the target

The source is [`../examples/Target.java`](../examples/Target.java). Copy it somewhere and build it:

```bash
# host
mkdir -p lab01 && cd lab01
cp ../examples/Target.java .
javac -d classes/ Target.java
d8 --release --output . classes/com/example/tour/*.class
ls -la classes.dex
```

`--release` matters. A debug build adds `.line` and `.local` directives on almost every instruction
and roughly doubles the length of the listing. You will build the debug version later and compare.

### Step 2 — Disassemble

```bash
# host
baksmali d classes.dex -o smali/
find smali -name '*.smali'
```

You should see `Target.smali` plus files for the nested types — `Target$Inner.smali`,
`Target$Tier.smali`, `Target$Check.smali`, and possibly a synthetic lambda class. **Note how many
files there are for one source file.** That ratio is worth remembering when you are estimating how
long an unfamiliar APK will take to read.

### Step 3 — Sanity check

```bash
# host
python3 ../scripts/smali_stats.py smali/ --top 20
python3 ../scripts/smali_frame.py smali/com/example/tour/Target.smali
```

Keep the frame output open in a second window. You are about to compute the same numbers by hand and
you want to be able to check yourself immediately.

---

## Part A — The register frame

Do these **on paper first**. Then check against `smali_frame.py`.

### A1. The rule

```text
    ins_size          = number of incoming argument WORDS
                        (instance methods add 1 for 'this';
                         each long or double counts as 2)

    first_param_reg   = registers_size - ins_size

    pN                = v(first_param_reg + N)
```

### A2. Compute these five

For each method, write down `ins_size`, `first_param_reg`, the full `p`-to-`v` map, and which
registers are free for locals. Open the Smali only to read the `.registers` value.

| # | Method | `.registers` in your build |
|---|---|---|
| 1 | `static boolean checkPin(String)` | look it up |
| 2 | `static int sum(int[])` | look it up |
| 3 | `static long expiry(long)` | look it up |
| 4 | `boolean transfer(String, long, String)` | look it up |
| 5 | `static long wide6(long, long, long)` | look it up |

**Answers for #4 and #5**, if your `.registers` matches the chapter's worked examples:

```text
    transfer(Ljava/lang/String;JLjava/lang/String;)Z   .registers 9
        instance -> 'this' counts
        this(1) + String(1) + long(2) + String(1) = ins_size 5
        first_param_reg = 9 - 5 = 4
            p0 == v4   this
            p1 == v5   to
            p2 == v6   amount, LOW half     the long occupies v6:v7
            p3 == v7   amount, high half
            p4 == v8   memo
            v0..v3 free

    wide6(JJJ)J                                        .registers 12
        static -> no 'this'
        long(2) + long(2) + long(2) = ins_size 6
        first_param_reg = 12 - 6 = 6
            p0 == v6,  p1 == v7     first long, v6:v7
            p2 == v8,  p3 == v9
            p4 == v10, p5 == v11
            v0..v5 free
```

> **The question that catches everyone.** In `transfer`, which register holds `memo`? It is **`p4`**,
> not `p3`, because the `long` consumed two `p` numbers. If you said `p3`, you counted commas instead
> of words — go back and redo all five.

### A3. Why the top and not the bottom?

Answer in a sentence before reading on.

<details>
<summary>Answer</summary>

Because it makes calls free. The caller places its outgoing arguments in a contiguous window at the
top of its own frame — that is what `outs_size` reserves — and the callee's frame is laid out so that
window *is* its parameter registers. No copying happens at a call. The price is that `p0`'s `v`
number depends on the total frame size, which is exactly the thing you change when you add a local
variable.

</details>

### A4. The trap, demonstrated

Open `Target.smali` and find `transfer`. Now answer:

1. Does the body refer to its parameters as `pN` or as raw `vN`?
2. If you raised `.registers 9` to `.registers 10`, which register would `this` move to?
3. What would happen to any line in the body that said `v4`?

Then run:

```bash
# host
python3 ../scripts/smali_frame.py smali/com/example/tour/Target.smali --check
```

Every `FRAGILE` line it reports is a raw `vN` that currently aliases a parameter. Those lines are
**correct today** and become **silently wrong** the moment you resize the frame. Read the tool's
explanation, then read §3.2 of the chapter again. This one mechanism causes more wasted hours than
anything else in Smali work.

---

## Part B — Line-by-line reading

### B1. `checkPin` — the simplest possible method

```bash
# host
sed -n '/checkPin/,/end method/p' smali/com/example/tour/Target.smali
```

You will see something close to:

```smali
.method public static checkPin(Ljava/lang/String;)Z
    .registers 3
    const-string v0, "1337"
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1
    return v1
.end method
```

Answer each of these in writing:

**Q1.** `.registers 3` with one incoming argument on a static method. What is `p0`'s `v` number?

**Q2.** In `invoke-virtual {v0, p0}`, which register is the *receiver* — the object the method is
called on — and which is the argument? What is the Java source line this corresponds to, and is it
`"1337".equals(pin)` or `pin.equals("1337")`?

**Q3.** Why is `move-result v1` a separate instruction? Why is the return value not written
into a register by the invoke?

**Q4.** What would happen if you inserted a `nop` between the `invoke-virtual` and the `move-result`?
At what moment would you find out?

<details>
<summary>Answers</summary>

**A1.** `first_param_reg = 3 - 1 = 2`, so `p0 == v2`. `v0` and `v1` are locals.

**A2.** The **first** register in the braces is the receiver. So `v0` — the constant `"1337"` — is the
receiver and `p0` is the argument. The source is `"1337".equals(pin)`, which is the null-safe
ordering a careful developer uses deliberately. If it had been `pin.equals("1337")` the braces would
read `{p0, v0}`.

**A3.** Because the invoke instruction's operand fields are already spent on the register list and the
`method_ids` index; there is no room in the encoding for a destination register. The return value is
handed over in a transient slot and `move-result` collects it. That is also why the two must be
adjacent — the slot is only valid at that instant.

**A4.** It would assemble fine and then fail **at class load** with a `VerifyError`, which you would
see the first time something used the class — not at install, not at build. `adb logcat -s art:*`
would name the method.

</details>

### B2. `sum` — the register-machine argument, measured

This is the exercise the whole chapter's §2.2 rests on, and doing it yourself is worth more than
reading it.

```bash
# host -- the JVM version
javap -c -p classes/com/example/tour/Target.class | sed -n '/static int sum/,/^$/p'

# host -- the Dalvik version
sed -n '/method static sum/,/end method/p' smali/com/example/tour/Target.smali
```

Fill in this table from what you see:

| | JVM (`javap`) | Dalvik (`baksmali`) |
|---|---|---|
| Instruction count | | |
| Byte count | | |
| Instructions that do no computation, only move values into position | | |

For the Dalvik byte count, add up the code units using the format table in
[12 §3.25](../../12-DEX-Internals/README.md) and double it. `const/4` is `11n` = 1 unit;
`array-length` is `12x` = 1; `if-ge` is `22t` = 2; `aget` is `23x` = 2; `add-int/2addr` is `12x` = 1;
`add-int/lit8` is `22b` = 2; `goto` is `10t` = 1; `return` is `11x` = 1.

You should land near **18 instructions / 24 bytes** for the JVM and **9 instructions / 24 bytes** for
Dalvik.

**Q5.** State, in one sentence each, what the register machine bought and what it cost.

**Q6.** Someone tells you "DEX files are smaller than JAR files because Dalvik bytecode is more
compact." Using your measurement, say precisely what is wrong with that sentence and what the real
reason is.

<details>
<summary>Answers</summary>

**A5.** It bought roughly half the instruction count, and therefore roughly half the interpreter
dispatch cycles — which on 2008-era ARM was the dominant per-instruction cost. It cost wider
instructions, because naming three registers takes bits an implicit stack does not spend.

**A6.** Per method, Dalvik's instruction stream is usually the same size or slightly *larger*. The
DEX size win comes almost entirely from **one shared constant pool for the whole application**
instead of one per class — each string, type, method and field name stored once rather than once per
class that mentions it. Conflating the two claims is a reliable way to be corrected in an interview.

</details>

### B3. `parse` — exception handling has no instructions

```bash
# host
sed -n '/method public static parse/,/end method/p' smali/com/example/tour/Target.smali
```

**Q7.** Find the `.catch` directive. Which instructions does it protect? Is the range inclusive or
exclusive at the `:try_end` end?

**Q8.** How many times does the `finally` body — the `trace("parse done")` call — appear in the
Smali? Why?

**Q9.** Find `move-exception`. Where exactly is it, and what would happen if you inserted a
`const-string` above it?

**Q10.** There is a `.catchall` directive with no exception type. What Java construct produced it?

<details>
<summary>Answers</summary>

**A7.** It protects everything from `:try_start_0` **up to but not including** `:try_end_0`. The range
is half-open. Note also that the directive appears *after* the region textually, because it is
describing a table entry rather than opening a block.

**A8.** At least twice, and often three times: once on the normal path, once in the typed
`NumberFormatException` handler, and once in the `catchall` that rethrows. The compiler duplicates
the body onto every exit path because there is no `finally` instruction. This is normal output, not
obfuscation.

**A9.** It is the **first** instruction of the handler, immediately after the `:catch_0` label. The
exception object is handed over in a slot that is only valid at handler entry, so anything above it
is a `VerifyError`. It is the exception-handling twin of the `move-result` adjacency rule.

**A10.** `finally`. A catch-everything handler that runs the body and rethrows is how `finally` is
implemented at bytecode level.

</details>

### B4. Both switches

```bash
# host
sed -n '/method public static route/,/end method/p' smali/com/example/tour/Target.smali
sed -n '/method public static status/,/end method/p' smali/com/example/tour/Target.smali
```

**Q11.** `route` uses `packed-switch` and `status` uses `sparse-switch`. What property of the case
values decided which one the compiler chose?

**Q12.** Find the `default` case in `route`'s Smali. Where is it?

**Q13.** In `status`, look at the `.sparse-switch` payload. The keys are `0xc8`, `0x194`, `0x1f4`.
Why must they be in that order?

**Q14.** Just before one of the payload labels there may be a bare `nop`. What is it for, and what
happens if you delete it?

<details>
<summary>Answers</summary>

**A11.** Density. `route`'s cases are 0, 1, 2 — consecutive — so a packed payload storing one
`first_key` and an array of targets makes lookup a single array index. `status`'s cases are 200, 404
and 500; a packed payload would need 301 entries, almost all pointing at the default, so the compiler
emits explicit key/target pairs instead.

**A12.** There is no default entry anywhere. Neither switch instruction encodes one. If the value
matches nothing, execution continues at the **next instruction after the switch** — so the
default body is sitting immediately below the `packed-switch` line.

**A13.** Because the runtime binary-searches the key array. Unsorted keys would make the search
return wrong answers, and the format specification requires ascending order.

**A14.** It is 4-byte alignment padding for the payload, which must be aligned. Deleting it is
harmless *if* the assembler re-inserts it, and produces a subtly different layout if it does not.
Either way, "cleaning up" a `nop` next to a payload label is a habit worth not developing.

</details>

### B5. `label` — the StringBuilder chain

```bash
# host
sed -n '/method public static label/,/end method/p' smali/com/example/tour/Target.smali
```

**Q15.** Count the instructions. The Java source was one `return` statement with four `+` operators.
Why is the bytecode this long?

**Q16.** After every `append` there is a `move-result-object` writing back into the *same* register
that was the receiver. Why?

**Q17.** Run the build again with a **high** `--min-api` and see whether the shape changes:

```bash
# host
d8 --release --min-api 26 --output d8-26/ classes/com/example/tour/*.class
baksmali d d8-26/classes.dex -o smali-26/
sed -n '/method public static label/,/end method/p' smali-26/com/example/tour/Target.smali
```

Does it still use `StringBuilder`, or did it become an `invoke-custom`? What does the answer tell you
about an unknown APK in which you see one or the other?

<details>
<summary>Answers</summary>

**A15.** Because Java's `+` on strings is not an operator on `String`; it is syntactic sugar for
building a `StringBuilder`, calling `append` once per operand, and calling `toString`. Every one of
those is an instruction, plus its `move-result-object`.

**A16.** Because `append` returns the builder itself, to allow chaining. The compiler threads the same
object through the chain rather than reloading it.

**A17.** Which one you get depends on the toolchain version and the `minSdk`, because D8 *desugars*
`invokedynamic`-based string concatenation back into a `StringBuilder` chain for lower API levels. So
seeing `invoke-custom` in an unknown APK tells you something about its build configuration — a
recent toolchain and a high `minSdk` — which is occasionally a useful fingerprint.

</details>

### B6. The key

**Q18.** Find `KEY` in the Smali. It is not a `const-string`. What is it?

```bash
# host
grep -n 'fill-array-data\|array-data' smali/com/example/tour/Target.smali
sed -n '/\.array-data/,/end array-data/p' smali/com/example/tour/Target.smali
```

**Q19.** Now try to find it the naive way:

```bash
# host
strings classes.dex | grep -i '2b7e\|key'
```

Why does that fail, and what is the general lesson for hunting hardcoded key material?

<details>
<summary>Answers</summary>

**A18.** A `new-array` followed by `fill-array-data` pointing at an `.array-data 1` payload — a
contiguous run of raw bytes parked in the instruction stream. The width `1` means `byte`.

**A19.** `strings` looks for runs of printable characters. Key material is arbitrary bytes and almost
never printable, so it is invisible. The general lesson: **`grep -rn 'fill-array-data' smali*/` finds
every array literal in an application in one command**, and it is one of the highest-yield searches
in Android reverse engineering. Chapter 12 covers the on-disk payload structure.

</details>

---

## Part C — Recognition drill

Open `Target.smali` and, **without looking at `Target.java`**, identify the source construct behind
each of these shapes. Write your answer, then check.

| # | Shape to find | Your answer |
|---|---|---|
| 1 | `invoke-static … Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;` | |
| 2 | A `sparse-switch` on the result of `hashCode()`, then `equals()`, then a `packed-switch` | |
| 3 | `monitor-enter` … `monitor-exit`, plus a `catchall` that also exits the monitor | |
| 4 | A `synthetic static` method whose whole body is one `sget`/`sput` and a return | |
| 5 | A class extending `Ljava/lang/Enum;` with a `synthetic static` field named `$VALUES` | |
| 6 | `instance-of` followed by `check-cast` on the same register | |
| 7 | `invoke-static/range {v0 .. v5}` | |
| 8 | A method named `lambda$makeChecker$0`, or a separate synthetic class | |
| 9 | An `.annotation system Ldalvik/annotation/Signature;` block on `firstOf` | |
| 10 | `rsub-int` rather than a subtraction | |

<details>
<summary>Answers</summary>

1. Autoboxing — an `int` being stored somewhere that needs an `Integer`.
2. `switch` on a `String`. The `const-string` values in the first stage are the real case labels; the
   `equals` calls exist because two different strings can share a hash.
3. `synchronized (lock) { … }` as a *block*. A synchronized *method* has no such instructions at all —
   the `declared-synchronized` access flag tells the runtime to take the lock on entry.
4. An `access$NNN` bridge: an inner class reaching the outer class's private `premium` field.
5. An `enum`. `$VALUES` is built in `<clinit>`.
6. `if (o instanceof String) { String s = (String) o; … }`.`check-cast` validates and does
   **not** write a register — it exists so the verifier can narrow the register's type.
7. `callWide()` calling `wide6(1L, 2L, 3L)`. Three longs is **six words**, past the five-word limit of
   the `35c` form, so the compiler had to use `/range` and had to lay the arguments out contiguously
   first.
8. The lambda in `makeChecker()`. Which form you see depends on desugaring.
9. Generic type information. Dalvik erases generics; `Ldalvik/annotation/Signature;` is the only
   record that `firstOf` took a `List<T>` and not a raw `List`.
10. `return 100 - r;` in `mix`. There is no `sub-int/lit8`, because `x - 5` is
    `add-int/lit8` with `-5`. What is needed is the reverse — `5 - x` — and that is `rsub-int`.

</details>

---

## Part D — Debug versus release

```bash
# host
d8 --debug --output debug/ classes/com/example/tour/*.class
baksmali d debug/classes.dex -o smali-debug/
wc -l smali/com/example/tour/Target.smali smali-debug/com/example/tour/Target.smali
diff smali/com/example/tour/Target.smali smali-debug/com/example/tour/Target.smali | head -60
```

**Q20.** Roughly what is the ratio in line count? Which directives account for the difference?

**Q21.** Which of those directives are **instructions**, and which are pure metadata?

**Q22.** If you found `.line` directives in quantity in a production APK, would that be a finding?
Argue both sides in two sentences.

<details>
<summary>Answers</summary>

**A20.** Typically between 1.5× and 2.5×. The extra lines are `.line`, `.local`, `.end local`,
`.restart local`, `.prologue` and `.param` name annotations.

**A21.** **None of them are instructions.** They are all debug metadata carried in the DEX's
`debug_info_item`, mapped to instruction offsets. They occupy space in the file and zero code units
in `insns`. That is why stripping them changes the file size and not the behaviour.

**A22.** For: it leaks the developer's source structure — file names, method names, and exact line
numbers — which materially assists an attacker, and MASVS-CODE treats retained debug artefacts as a
weakness. Against: it is information disclosure of low direct impact, it does not by itself create an
exploitable condition, and many apps ship it deliberately so crash reports are usable. Report it,
with honest severity: Low or Informational, unless the app also relies on obscurity for something
else.

</details>

---

## Success criteria

You are done when you can, without notes:

- [ ] Compute `first_param_reg` and the full `p`-to-`v` map for any method signature.
- [ ] Explain why `transfer`'s second `String` is `p4` and not `p3`.
- [ ] State the `move-result` adjacency rule and say **when** violating it is discovered.
- [ ] Point at a `try`/`finally` in Smali and explain why the body appears more than once.
- [ ] Say where a `switch`'s default case lives.
- [ ] Find every hardcoded byte array in an app with one `grep`.
- [ ] Recite the honest version of the register-machine trade-off, with your own measured numbers.
- [ ] Explain why `.line` directives are not instructions.

## Common ways this lab goes wrong

| Symptom | Cause |
|---|---|
| `d8` complains about class file version | Your JDK is newer than the `d8` you have. Compile with `javac --release 8` |
| `baksmali` refuses the DEX | Version mismatch. Pass `--api 34`, or update `baksmali` |
| Register numbers do not match the answers above | Your `d8` allocated differently. That is fine — recompute from *your* `.registers` value. The **method** is what matters, not the numbers |
| The lambda produced no separate class | Desugaring chose `invoke-custom`. Look for it, and for a `lambda$…$0` synthetic method |
| `smali_frame.py` reports `FRAGILE` on lines you did not write | Correct. Those are `baksmali`'s raw `vN` references to parameters. Read the tool's explanation |

## Next

[Lab 02 — Patch, rebuild, verify](lab-02-patch-and-rebuild.md) takes the same class into an APK and
makes you change its behaviour on a real device.
