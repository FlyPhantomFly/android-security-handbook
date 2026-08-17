# Example 02 — When jadx is wrong

All three of jadx's failure modes, reproducible in twenty seconds with **jadx and a JDK only**.
No apktool, no `smali.jar`, no Android SDK, no device — jadx bundles a Smali assembler, so the
`.smali` files here are complete, self-contained inputs.

```bash
# host
export JADX_JAR="C:/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar"   # or leave unset if jadx is on PATH
./reproduce.sh
```

| File | Demonstrates |
|---|---|
| [`Irreducible.smali`](Irreducible.smali) | **Refusal** — a loop with two entry points; and the `--show-bad-code` trap |
| [`Accumulate.smali`](Accumulate.smali) | **Silence** — clean Java, no warning, wrong answer |
| [`VariantV4.smali`](VariantV4.smali) | The narrowing experiment, and the honest statement of what it did not establish |
| [`Obfuscated.smali`](Obfuscated.smali) | What `--deobf` actually does; how a `native` declaration renders |
| [`Proof.java`](Proof.java) | Runs both readings of `Accumulate` on the JVM and prints the divergence |
| [`reproduce.sh`](reproduce.sh) | Runs everything above and prints it side by side |

Chapter sections: [§3.7](../../README.md#37-the-decompilation-mode-ladder),
[§3.8](../../README.md#38---show-bad-code-and-why-it-can-make-things-worse),
[§3.9](../../README.md#39---deobf-does-not-deobfuscate),
[§6.4](../../README.md#64-failure-mode-one-refusal),
[§6.5](../../README.md#65-failure-mode-two-warned-wrongness),
[§6.6](../../README.md#66-failure-mode-three-silence).

---

## 1. Refusal — the loud failure

`Irreducible.irreducible` is a loop entered at two different places. Java has no `goto`, so every
control-flow graph `javac` or `kotlinc` can produce is *reducible* — every loop has exactly one entry.
This one has two. **There is no Java program with this shape**, so jadx is not failing to be clever
enough; it is failing to express something the target language cannot express.

jadx 1.5.3, default settings:

```java
/* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:8:0x000a -> B:4:0x0003).
   Please report as a decompilation issue!!! */
/*
    Code decompiled incorrectly, please refer to instructions dump.
    To view partially-correct add '--show-bad-code' argument
*/
public static int irreducible(int r4, int r5) {
    /*
        r0 = 0
        if (r4 == 0) goto L8
    L3:
        int r0 = r0 + 1
        if (r0 >= r5) goto Ld
        goto L8
    L8:
        int r0 = r0 + 2
        if (r0 >= r5) goto Ld
        goto L3
    Ld:
        return r0
    */
    throw new UnsupportedOperationException("Method not decompiled: com.pentest.ch56.Irr.irreducible(int, int):int");
}
```

This is **good** behaviour. jadx names the pass's finding, names the exact back edge, prints the code
it lost, gives you a complete instruction dump, and replaces the body with something nobody could
mistake for working code.

### The `--show-bad-code` trap

Everybody learns this flag as "the one that shows you the broken methods". Run the same input with it:

```java
/* ... the same JADX WARN comments ... */
/*
    Code decompiled incorrectly, please refer to instructions dump.
*/
public static int irreducible(int i, int i2) {
    int i3 = 0;
}
```

The instruction dump is **gone**, and the body assigns zero to an unused local and falls off the end
without returning. Skim past the comment block and that reads as "this method does nothing".

`--show-bad-code` does not show more truth. It shows jadx's best guess *instead of* the dump, and on a
badly-failed method the guess is worse than the dump. Use it for a large method that failed on one
branch; never as your reading mode for a method you intend to make a claim about.

### The escalation ladder

`reproduce.sh` runs all four modes on the same method:

| Mode | Result on `irreducible` |
|---|---|
| default (`auto`) | Refusal + complete instruction dump |
| `--show-bad-code` | A body that appears to do nothing |
| `-m simple` | Linear Java with labels and explicit `goto`s. Always produces something |
| `-m fallback` | Register-level near-disassembly with catch ranges annotated |

Trustworthiness increases down that table and readability decreases. That is the whole reason there
are four modes.

---

## 2. Warned wrongness — the middle case

The same file's second method, `overlapping`, has an exception handler that jumps back *into* its own
protected region. jadx does **not** refuse it. It prints:

```java
public static int overlapping(String str) {
    int i = 0;
    while (true) {
        try {
            return i + str.length() + str.hashCode();
        } catch (Exception e) {
            i += 100;
        }
    }
}
```

Plausible. Compiles. And `-m fallback` on the same method shows the two accumulation steps as separate
instructions inside the try region, which the Java has folded into one expression. Whether that
matters here depends on which of the two calls throws — which is exactly the class of question the
Java can no longer answer, and exactly the reason for section 3.

---

## 3. Silence — the dangerous failure

`Accumulate.accumulate` is an accumulator, two array reads inside a `try`, and a handler that adds
100 to whatever the accumulator holds.

Trace it for `xs = {5}`: `xs[0]` succeeds so `acc = 5`; `xs[1]` throws; the handler adds 100; the
method returns **105**.

jadx 1.5.3 prints, with **no warning of any kind**:

```java
public class Acc {
    public static int accumulate(int[] iArr) {
        try {
            return 0 + iArr[0] + iArr[1];
        } catch (Exception e) {
            return 0 + 100;
        }
    }
}
```

which returns **100**.

### Proof by execution

`Proof.java` writes both readings as Java and runs them:

```
original(new int[]{5})    = 105
jadx output(new int[]{5}) = 100
original(new int[]{5,7})    = 12
jadx output(new int[]{5,7}) = 12

DIVERGENCE on the exception path: 105 vs 100  -- and jadx printed no warning.
```

Identical on the happy path. Different by 5 on the exception path. **This is what a silent
decompilation failure looks like: not garbage, not a warning — a five.**

### The tell

`return 0 + iArr[0] + iArr[1]` and `return 0 + 100`. A human writes `return iArr[0] + iArr[1]` and
`return 100`. The leading `0 +` is the residue of an accumulator that jadx folded into the
expressions — and **an accumulator inside a `try` is exactly where an exception edge can observe a
partial value.**

The responsible pass is almost certainly `CodeShrinkVisitor`, which folds a value's definition into
its single use and runs twice in the standard pipeline (see chapter §4.3). Folding is sound unless
something observes the intermediate value. An exception edge observes it.

### What this experiment did not establish

`VariantV4.smali` is the same program written with the **exact register allocation `javac` + `d8`
produce**. `jadx -m fallback` renders it and the compiler's own DEX *identically* — same registers,
same catch range, same branch targets. Yet jadx decompiles the compiler's DEX correctly and this file
incorrectly. Three further variants (three-address `add-int` instead of `/2addr`; a different register
count; a handler with no `move-exception`) all behaved like `VariantV4`.

So the trigger lives somewhere the fallback dump does not show, and this was not isolated. Two caveats
belong with any report of it:

1. These inputs reach jadx through **jadx's own `smali-input` assembler**. A difference introduced by
   the assembler rather than the decompiler has not been ruled out.
2. The right destination for a reproducible divergence is a **minimal reproducer on the project's
   issue tracker** — <https://github.com/skylot/jadx/issues> — not an assertion that the tool is
   broken. The maintainer can see internal state; you cannot.

### Why it matters anyway

The operational conclusion does not depend on the cause, and it is the load-bearing claim of the
whole chapter:

> jadx's correctness is a property of the **shape of the bytecode**, not of the semantics of the
> program. Bytecode `d8` emits is inside the envelope jadx is tuned for. Bytecode from an obfuscator,
> a packer, a hand patch, a different compiler or a bytecode-rewriting SDK is outside it. **And the
> Java gives you no way to tell which case you are in**, because the failure prints no warning.

That is why the rule is *read Java to find, read Smali to be certain*, and why
[14 — Dalvik](../../../14-Dalvik/README.md) is a chapter you work through rather than a reference you
skim.

### Where you meet this shape for real

The exception-edge case above is the cleanest demonstration, not the most common occurrence. The
general pattern — a readability transformation erasing an intermediate state — turns up in:

- Retry loops with a counter mutated inside a `try`.
- Crypto routines where a buffer is partially filled before an exception.
- Any `finally` that reads a variable the `try` was in the middle of updating.
- Resource cleanup where "how far did we get" determines what gets cleaned.

All four are places where a security claim depends on partial state — which is exactly where you were
going to be careful anyway.

---

## 4. `--deobf` does not deobfuscate

`Obfuscated.smali` is a class `a` in package `a.b`, with a field `a`, a method `a`, and a `native`
method `b`.

Without `--deobf`:

```java
package a.b;

public class a {

    /* renamed from: a, reason: collision with root package name */
    private static String f0a;

    public static String a(String str) {
        return str;
    }

    public native int b();
}
```

With `--deobf`:

```java
package p000a.p001b;

/* renamed from: a.b.a */
public class C0000a {

    /* renamed from: a */
    private static String f0a;

    /* renamed from: a */
    public static String m0a(String str) {
        return str;
    }

    /* renamed from: b */
    public native int m1b();
}
```

The second is harder to read and recovers nothing. What it buys is real but different: **uniqueness**.
`m0a` is unique across the whole app where `a` is not, so cross-referencing works, diffs between app
versions mean something (with a shared `--deobf-cfg-file`), and the field/method collision is gone.

Two further things in that first listing are worth noticing:

- **jadx renamed the field even with no flag.** `/* renamed from: a, reason: collision with root
  package name */` is `--rename-flags`, which is on by default because the output has to be
  self-consistent Java. jadx renames things you did not ask it to rename — and always says so in a
  comment.
- **`public native int b();`** — a `native` method decompiles to a declaration with no body. That one
  line is the boundary between this chapter and [16-JNI](../../../16-JNI/README.md) /
  [57-Ghidra](../../../57-Ghidra/README.md). See chapter §6.9.

---

## Artefact policy

`reproduce.sh` writes everything under `./_out` (or a directory you name). No `.class`, `.dex` or
`.apk` is written into the repository.
