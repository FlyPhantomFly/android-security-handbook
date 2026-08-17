# SOLUTION — Lab 04, "The Honest Decompiler"

> **Spoilers.** Do not read this until you have a flag you believe in. The brief is
> [`../lab-04-ctf-honest-decompiler.md`](../lab-04-ctf-honest-decompiler.md).

**Flag:** `CTF{the_bytecode_never_lies}`

---

## What jadx 1.5.3 prints

```java
package com.pentest.ch56.ctf;

public class Vault {
    public static final String BANNER = "CTF{read_the_java_and_stopped}";

    public static String flag() {
        byte[] bArr = {39, 48, 29, 46, 43, 39, 49, 63, 1, 22, 4, 57, 54, 42, 39, 29, 32, 59, 54, 39, 33, 45, 38, 39, 29, 44, 39, 52};
        int iSeed = seed();
        int iRounds = rounds(iSeed & 1);
        char[] cArr = new char[28];
        for (int i = 0; i < 28; i++) {
            cArr[i] = (char) (bArr[(i + iRounds) % 28] ^ iSeed);
        }
        return new String(cArr);
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:8:0x000c -> B:4:0x0005). */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
    */
    public static int rounds(int r3) {
        /*
            r0 = 0
            r1 = 7
            if (r3 == 0) goto La
        L5:
            int r0 = r0 + 1
            if (r0 >= r1) goto Lf
            goto La
        La:
            int r0 = r0 + 2
            if (r0 >= r1) goto Lf
            goto L5
        Lf:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: ...");
    }

    public static int seed() {
        int[] iArr = {53};
        try {
            return 0 + iArr[0] + iArr[1];
        } catch (Exception e) {
            return 0 + 13;
        }
    }
}
```

Three methods, three different levels of truth in one file. That is the whole design.

---

## Stage 0 — the decoy

`BANNER` is a `String` constant matching `CTF{`. `grep -r "CTF{" out/` finds it in half a second.

**Nothing in the class references it.** `flag()` does not read it; no other method exists. It is
unreachable data, and its content — `CTF{read_the_java_and_stopped}` — names the mistake.

**The habit being trained:** searching an output tree finds *strings*. Reading it finds *behaviour*.
A constant nothing uses is not a finding; it is a string. Check the cross-references before you
believe a literal. In jadx-gui this is right-click → Find Usage, one keystroke.

---

## Stage 1 — the silent failure: `seed()`

jadx's version:

```java
public static int seed() {
    int[] iArr = {53};
    try {
        return 0 + iArr[0] + iArr[1];
    } catch (Exception e) {
        return 0 + 13;
    }
}
```

`iArr` has one element, so `iArr[1]` throws `ArrayIndexOutOfBoundsException`, so the `catch` runs, so
this returns **13**.

The bytecode:

```smali
    const/4 v0, 0x1
    new-array v1, v0, [I
    const/4 v2, 0x0
    const/16 v3, 0x35        # 53
    aput v3, v1, v2          # arr[0] = 53
    const/4 v0, 0x0          # acc = 0
:try_start
    const/4 v2, 0x0
    aget v2, v1, v2          # 53
    add-int/2addr v0, v2     # acc = 53      <-- LIVE ON THE EXCEPTION EDGE
    const/4 v2, 0x1
    aget v2, v1, v2          # THROWS
    add-int/2addr v0, v2
:try_end
    goto :out
:handler
    move-exception v4
    add-int/lit8 v0, v0, 0xd # acc = 53 + 13 = 66
:out
    return v0
```

**Real answer: 66 (0x42). jadx's answer: 13.**

`CodeShrinkVisitor` folded the accumulator into the return expressions, which is sound unless
something observes the intermediate value. An exception edge observes it. **No `JADX WARN` comment is
emitted.** Chapter §6.6 walks the same shape in isolation, with a proof by execution.

**The tell:** `return 0 + iArr[0] + iArr[1];` and `return 0 + 100;`-style leading constants. A human
writes `return 13;`. A leading constant term in a folded expression inside a `try` is the residue of
an accumulator, and an accumulator inside a `try` is exactly where a partial value can be observed.

---

## Stage 2 — the loud failure: `rounds(int)`

jadx refuses it: irreducible control flow, a loop with two entry points, which no Java program has
(chapter §3.5). But it prints the complete instruction dump, so you can hand-trace it.

`flag()` calls `rounds(seed & 1)`. With the **correct** seed, `66 & 1 == 0`:

| Step | Where | `r0` after | Test |
|---|---|---|---|
| entry | `r3 == 0`, so `goto La` | 0 | — |
| 1 | `La`: `r0 += 2` | 2 | `2 >= 7`? no → `goto L5` |
| 2 | `L5`: `r0 += 1` | 3 | `3 >= 7`? no → `goto La` |
| 3 | `La`: `r0 += 2` | 5 | `5 >= 7`? no → `goto L5` |
| 4 | `L5`: `r0 += 1` | 6 | `6 >= 7`? no → `goto La` |
| 5 | `La`: `r0 += 2` | 8 | `8 >= 7`? **yes** → `Lf` |

**`rounds(0) = 8`.**

Had you kept jadx's seed of 13, then `13 & 1 == 1`, you enter at `L5` instead, and the trace gives
**`rounds(1) = 7`** — wrong entry point, wrong answer, and the two errors compound.

`-m simple` gives a linear rendering of the same method, and `-m fallback` a near-disassembly. Either
is faster to trace than the comment dump. Chapter §3.7 orders all four modes by trustworthiness, and
this method is a good place to see why the ordering matters.

---

## Stage 3 — decode

```python
# host — python3 -B
enc = [39,48,29,46,43,39,49,63,1,22,4,57,54,42,39,29,32,59,54,39,33,45,38,39,29,44,39,52]
n, seed, rounds = len(enc), 66, 8
print("".join(chr(enc[(i + rounds) % n] ^ seed) for i in range(n)))
# CTF{the_bytecode_never_lies}
```

---

## The four ways to get it wrong, and what each one tells you

| What you submitted | Where you stopped | The habit it exposes |
|---|---|---|
| `CTF{read_the_java_and_stopped}` | Stage 0 | You searched the output instead of reading it, and did not check cross-references |
| Mojibake | Stage 1, seed 13 and rounds 7 | You trusted warning-free decompiled Java |
| Mojibake | seed 13, rounds 8 | You caught the loud failure and missed the silent one — the common case |
| `}CTF{the_bytecode_never_lies` | seed 66, rounds 7 | You caught the silent failure and mis-traced the loud one. **The challenge tells you so**: an off-by-one rotation is visibly the flag with its ends swapped |

That last row is deliberate. A wrong answer that is *nearly* right is the most useful kind of
feedback, and recognising "this is almost the flag, so one of my two inputs is nearly right" is a
real reverse-engineering skill.

---

## The point

Three methods, three levels of truth, all in one file with no visual distinction between them:

| Method | jadx | Trust |
|---|---|---|
| `flag()` | Decompiled perfectly | Correct |
| `rounds(int)` | Refused, loudly, with a complete dump | Safe — you were told |
| `seed()` | Clean, idiomatic, no warnings | **Wrong** |

The one you can least afford to get wrong is the one that looks best.

> jadx's warnings are a **floor** on its error rate, not a ceiling. A file with no `JADX WARN`
> comments is not a file that decompiled correctly; it is a file where jadx had no doubts. Those are
> different statements, and the difference is where findings go wrong.

Which is why the rule is: **find it in Java, confirm it in Smali, prove it at runtime**
(chapter §5.4), and why [14 — Dalvik](../../../14-Dalvik/README.md) is a chapter you work through
rather than a reference you skim.

---

## How the challenge was built

Both failure shapes are the ones chapter 56 measured directly:

- `seed()` reuses [`examples/02-when-jadx-is-wrong/Accumulate.smali`](../../examples/02-when-jadx-is-wrong/Accumulate.smali)'s
  shape with values chosen so the divergence is a usable key: `53 + 13 = 66 = 0x42`, while jadx's
  reading gives `13`.
- `rounds(int)` reuses [`Irreducible.smali`](../../examples/02-when-jadx-is-wrong/Irreducible.smali)'s
  two-entry loop with a limit of 7, so the two entry points give 8 and 7 respectively.

The caveat from chapter §6.6 applies here too and is worth repeating: these inputs reach jadx through
jadx's own `smali-input` assembler, so "the decompiler is wrong" is the operational reading, not a
fully isolated claim about which component is responsible. The lesson — *you cannot tell from the
Java* — does not depend on resolving that.
