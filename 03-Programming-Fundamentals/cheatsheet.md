# 03 — Programming Fundamentals — Cheat Sheet

Printable. Tables and commands only. Explanations in [README.md](README.md).

---

## 1. Primitive types — memorise this table

| Type | Bits | Signed? | Range | Notes |
|---|---|---|---|---|
| `boolean` (Java) | 1 logical / 8+ actual | — | `true` / `false` | Not addressable as a bit |
| `byte` (Java) / `int8_t` | 8 | Signed | −128 … 127 | Java has **no unsigned byte** — this catches everyone |
| `char` (Java) | 16 | Unsigned | 0 … 65 535 | A UTF-16 code unit, **not** a character |
| `char` (C) | 8 | Implementation-defined | −128…127 or 0…255 | Signedness varies by platform |
| `short` | 16 | Signed | −32 768 … 32 767 | |
| `int` | 32 | Signed | **−2 147 483 648 … 2 147 483 647** | The one that overflows |
| `long` (Java) | 64 | Signed | ±9.22 × 10¹⁸ | |
| `long` (C) | 32 or 64 | Signed | Platform-dependent | Use `int64_t` when it matters |
| `size_t` (C) | 32 or 64 | **Unsigned** | 0 … 2ⁿ−1 | A negative `int` cast here becomes enormous |
| `float` | 32 | — | ~7 decimal digits | Never for money |
| `double` | 64 | — | ~15 decimal digits | Never for money |
| Pointer / reference | 32 or 64 | — | An address | 8 bytes on arm64 |

**Two's complement:** the top bit is the sign. Negate by inverting all bits and adding 1.
`-1` is all ones (`0xFFFFFFFF` as a 32-bit int).

## 2. Overflow quick reference

| Expression | 32-bit signed result |
|---|---|
| `2147483647 + 1` | `-2147483648` |
| `-2147483648 - 1` | `2147483647` |
| `200000000 * 16` | `-1094967296` |
| `(size_t)(-1)` on 64-bit | `18446744073709551615` |
| `Math.abs(Integer.MIN_VALUE)` | `Integer.MIN_VALUE` (still negative) |

**Danger sites:** allocation sizes, length checks, loop bounds, array indices, timestamps in ms.

**Safe patterns:**

```c
if (__builtin_mul_overflow(a, b, &result)) { /* reject */ }   /* GCC / Clang */
buf = calloc(count, size);                                    /* checks internally */
```
```java
int r = Math.multiplyExact(a, b);   // throws ArithmeticException on overflow
long r = (long) a * (long) b;       // widen BEFORE multiplying, not after
```

---

## 3. Where things live

| | Stack | Heap | Static / .data / .rodata |
|---|---|---|---|
| Allocated by | Function entry | `malloc` / `new` | The loader, at start-up |
| Freed by | Function return | `free` / GC | Process exit |
| Speed | One instruction | Slow | — |
| Size | 1–8 MB per thread | GBs | Fixed at build time |
| Holds | Locals, parameters, return addresses | Objects, arrays, anything dynamic | Globals, string literals |
| Security relevance | Return addresses next to buffers | Secrets that outlive their function | Hardcoded keys |

---

## 4. Control flow → machine

| Source | Becomes |
|---|---|
| `if (a > b) X else Y` | `cmp a, b` ; `b.le else_label` ; X ; `b end` ; `else_label:` Y ; `end:` |
| `while (c) { B }` | `test:` `cmp` ; `b.<fail> done` ; B ; `b test` ; `done:` |
| `for (i=0; i<n; i++)` | Same as `while`, with the increment before the backward branch |
| `switch` (dense cases) | A **jump table**: one indexed indirect branch |
| `switch` (sparse cases) | A chain of comparisons, or a binary search |
| `a && b` | Short-circuit: `b` is not evaluated if `a` is false |
| Function call | Args to registers per the ABI ; `bl target` (saves return addr in `lr`) |
| Function return | `ret` (branch to `lr`) |

**Loop shape in any disassembly:** a compare, a *forward* conditional branch (the exit), and a
*backward* unconditional branch (the repeat).

---

## 5. Big-O

| Complexity | Name | Example | n = 1 000 000 |
|---|---|---|---|
| O(1) | Constant | Array index, hash lookup | 1 |
| O(log n) | Logarithmic | Binary search, balanced tree | 20 |
| O(n) | Linear | Scan a list | 10⁶ |
| O(n log n) | Linearithmic | Good sorting | 2 × 10⁷ |
| O(n²) | Quadratic | Nested loop, bubble sort | 10¹² |
| O(2ⁿ) | Exponential | Naive subset search | Unusable |

**Security use:** an O(n²) path reachable from hostile input is a denial of service. Hash collision
DoS turns O(1) into O(n).

---

## 6. Data structures

| Structure | Lookup | Insert | Delete | Memory | Where you meet it |
|---|---|---|---|---|---|
| Array | O(1) by index | O(n) | O(n) | Contiguous, minimal | DEX tables, `byte[]` |
| Linked list | O(n) | O(1) at a known node | O(1) at a known node | Pointer per node | Free lists, `LinkedList` |
| Stack | — | O(1) | O(1) | — | The call stack itself |
| Queue | — | O(1) | O(1) | — | Message loops, Binder |
| Hash map | O(1) avg / O(n) worst | O(1) avg | O(1) avg | ~1.5× entries | `HashMap`, ART intern table |
| Balanced tree | O(log n) | O(log n) | O(log n) | Pointer overhead | `TreeMap`, indexes |
| Sorted array | O(log n) binary search | O(n) | O(n) | Minimal | **DEX string pool** |

**Java string hash** — reproduce it exactly:

```
h = 0
for each char c:  h = h * 31 + c        # 32-bit signed, wraps
```

---

## 7. Pointers and references

| | C pointer | Java reference |
|---|---|---|
| Arithmetic | Yes (`p + 1`) | No |
| Cast from an integer | Yes | No |
| Manual free | Yes (`free(p)`) | No — GC |
| Bounds-checked access | No | Yes |
| Null | Yes → undefined behaviour | Yes → `NullPointerException` |
| Points into the middle of an object | Yes | No |

**The four ways pointers kill you:** buffer overflow, use after free, double free, null dereference.
Java prevents the first three **inside managed code only**. All four return at the JNI boundary.

---

## 8. Memory management

| | Manual (C/C++) | Garbage collected (Java/Kotlin) |
|---|---|---|
| Freed when | You say so | Nothing can reach it |
| Use after free | Possible | Impossible |
| Double free | Possible | Impossible |
| Leaks | Possible | Possible (unreachable ≠ unreferenced) |
| Zero a secret | **Yes, deterministically** | **No** — `String` is immutable |
| Pauses | None | Yes, non-deterministic |
| Objects move | No | **Yes**, under a copying collector |

**Secrets:** `char[]` zeroed in a `finally` block, never `String`. Best: never let the key enter the
process — use the Keystore.

---

## 9. Encodings

| Encoding | Unit | Used by | Trap |
|---|---|---|---|
| ASCII | 7 bits | Everything, as a base | Only 128 characters |
| UTF-8 | 1–4 bytes | Files, network, the web | Length in bytes ≠ length in characters |
| UTF-16 | 2 or 4 bytes | **Java `String` in memory** | `length()` counts code *units*, so an emoji is 2 |
| MUTF-8 | 1–3 bytes | **DEX string pool** | NUL is `0xC0 0x80`; supplementary chars are surrogate pairs |
| Latin-1 | 1 byte | Legacy | Silent mojibake |

---

## 10. Reading a stack trace

```
ExceptionType: message
    at where.it.broke(File.java:LINE)      <- top APPLICATION frame = where it broke
    at framework.frames(...)               <- ignore
Caused by: RootCauseException              <- READ THIS FIRST
    at the.actual.bug(File.java:LINE)      <- the bug is usually here
```

1. Read the **last** `Caused by` — that is the root cause.
2. Then the **topmost frame in a package you own** — that is where it manifested.
3. Frames between are transport.

---

## 11. Debugging commands

```bash
# host — C: let the compiler find it for you
gcc -fsanitize=undefined,address -g prog.c -o prog && ./prog
gcc -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 prog.c

# host — gdb / lldb essentials
gdb ./prog
  break file.c:42          # or:  break function_name
  run <args>
  next / step / finish     # over / into / out
  print expr               # print (unsigned long)size
  backtrace
  watch variable           # break when it changes  <-- the underused one
  info locals

# host — bisect a regression in git
git bisect start
git bisect bad
git bisect good <known-good-commit>
# ...test, then `git bisect good` or `git bisect bad` until it names the commit
git bisect reset

# host — what did this compile to?
javap -c -p -cp . MyClass          # JVM bytecode
gcc -O0 -S prog.c -o -             # assembly
objdump -d ./prog | less           # machine code, disassembled
readelf -h ./prog                  # ELF header
xxd prog | head                    # the raw bytes
```

```bash
# adb shell — Android native crash
logcat -b crash
logcat | ndk-stack -sym ./obj/local/arm64-v8a      # symbolise a native trace
```

---

## 12. Git — the commands that find secrets

```bash
# host
git log --all --diff-filter=D --name-only --pretty=format: | sort -u \
  | grep -Ei 'key|secret|env|\.properties|\.jks|\.keystore|credential'

git log --all --oneline -S 'BEGIN RSA PRIVATE KEY'      # commits adding/removing this string
git log --all --oneline -S 'AKIA'                       # AWS key IDs
git show <commit>:path/to/deleted/file                  # read a deleted file back
git reflog                                              # where HEAD has been
git fsck --lost-found                                   # unreferenced objects
```

**Remember:** git almost never deletes. Removing a secret in a later commit does not remove it from
history, and it has already been cloned.

---

## 13. Reading code you did not write — the five moves

| Move | Do | Command |
|---|---|---|
| 1. Entry points | Find where execution begins | `grep -n 'exported="true"' AndroidManifest.xml` |
| 2. Find the data | Find storage, network, crypto | `grep -rn 'getSharedPreferences\|SQLiteDatabase\|Cipher\|OkHttpClient'` |
| 3. Follow the state | Created / stored / read / destroyed | Fill the four-row table; an empty row is the finding |
| 4. Ignore the noise | Skip libraries, UI, analytics, getters | `grep -v -E '/(androidx\|kotlin\|okhttp3\|com/google)/'` |
| 5. Name what you learn | Notes file + rename in the tool | Four sections: entry points, data, state, open questions |

**Never skip:** anything named `*Security*`, `*Crypto*`, `*Auth*`, `*Token*`, `*Key*`, `*Session*`;
anything `native`; anything parsing bytes; custom `TrustManager`/`HostnameVerifier`; `WebView`
configuration; reflection; `Runtime.exec`, `DexClassLoader`, `System.load`.

---

## 14. Translation strategies

| | Interpretation | AOT native | Bytecode VM | JIT |
|---|---|---|---|---|
| Translated | Every run | Build time | Build time | Run time, when hot |
| Ships | Source | Machine code | Bytecode | Bytecode |
| Startup | Instant | Instant | Fast | Fast |
| Peak speed | Lowest | Highest | Low | High after warm-up |
| Symbols survive | Everything | Almost nothing | Names + types | Names + types |
| Android | `sh` scripts | NDK `.so`, `dex2oat` output | DEX in the interpreter | ART JIT cache |
| RE difficulty | Trivial | Hard | Easy | Easy |

**Android uses all of them at once**, chosen per method at runtime.

---

## 15. Rules to keep

| Rule | Because |
|---|---|
| `.equals()` not `==` for Java strings | `==` compares references; literals are interned so the bug hides |
| `SecureRandom` not `Random` | `Random` is an LCG — observe two outputs, predict all the rest |
| `char[]` not `String` for secrets | `String` cannot be zeroed and may be interned |
| Never `catch (Exception e) {}` | Converts a bug into an invisible bug |
| Never float for money | Binary cannot represent 0.1 exactly |
| `<` not `<=` against a length | The classic off-by-one |
| Bound recursion depth | Attacker-controlled nesting is a one-input DoS |
| Widen before multiplying | `(long)a * b`, not `(long)(a * b)` |
| Turn on sanitisers | Finds in one second what review misses in an hour |
| Write it down | You will lose your understanding overnight |
