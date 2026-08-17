# 56 — JADX · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask, which are
usually the ones worth asking.

Chapter: [README.md](README.md) · [cheatsheet.md](cheatsheet.md) · [mindmap.md](mindmap.md)

---

### 1. Is this the real source code?

**No.** It is a reconstruction, and the distinction is not pedantry — it changes what you may
conclude from it.

Think of what shipped. The developer had `.java` and `.kt` files with comments, meaningful variable
names, whitespace and a mental model. What is inside the APK is a `classes.dex`: an instruction
stream for a register machine plus enough metadata for the runtime to resolve references. The
comments are gone. The formatting is gone. Local variable names are gone unless the build kept debug
information. Generic type arguments are gone from expressions. There is nothing to invert.

So jadx synthesises. It reads the instructions, builds a control-flow graph, infers types the
bytecode never recorded, invents names, fits Java statements over the graph's shape, and prints a
program that — if all went well — **behaves the same way**. That program is a good hypothesis. On
`AccountVault` (chapter §6.2, measured) the logic came back perfectly and every single name was
invented.

The practical consequence: decompiled Java is excellent for **finding** things and insufficient for
**being certain** of them. See question 6.

---

### 2. Why does jadx say "decompilation failed" / "Method not decompiled"?

Because for that method, **no Java program exists.**

Java has no `goto`. Every control-flow graph that `javac` or `kotlinc` can produce from structured
source is therefore *reducible* — every loop has exactly one entry point. Dalvik bytecode has `goto`
and can express graphs that are not reducible: loops with two entries, jumps into the middle of a
try block, handlers that branch back into their own protected region.

jadx's job is to fit `if`, `for`, `while`, `switch` and `try` over the graph. When the graph has no
such shape, there is nothing to print. So it prints a complete instruction dump in a comment,
explains what it could not do, and replaces the body with
`throw new UnsupportedOperationException("Method not decompiled: ...")`.

**That is good behaviour, not a bug.** You have been told exactly where you stand. What to do:

1. Read the instruction dump — it is complete, and it is often enough.
2. `-m simple` — linear Java with labels and explicit `goto`s. Never refuses.
3. `-m fallback` — near-disassembly with catch ranges annotated.
4. Real Smali via `apktool`/`baksmali` → [14 — Dalvik](../14-Dalvik/README.md).

On a real 17.5 MB app, 2,104 methods out of roughly 150,000 were refused. It is normal. What matters
is *where* they are (chapter §8.5).

---

### 3. Why are all the names `a`, `b`, `c`?

The build ran **R8** (or its predecessor ProGuard) with obfuscation enabled, which renames every
identifier it is permitted to rename. jadx is faithfully showing you the names that are in the file.

Note carefully what is and is not R8's doing:

| Missing thing | Cause |
|---|---|
| Class, method and field names replaced by `a`, `b`, `c` | **R8** |
| Local variable names replaced by `str2`, `i2`, `cArr` | **Not R8.** Debug info was stripped — see question 8 |
| Generic type arguments on `new` expressions | **Not R8.** Type erasure, at compile time |
| Comments | **Not R8.** Gone at the first compile |

Four independent losses, one of which obfuscation caused. Attributing all four to obfuscation is the
most common misconception in this area, and it leads people to ask for the wrong remediation.

---

### 4. Does `--deobf` un-obfuscate the app?

**No.** It is the most misleadingly-named flag in the tool.

Measured (chapter §3.9), a class `a` in package `a.b` with a field `a` and a method `a`:

```java
// without --deobf
package a.b;
public class a {
    private static String f0a;
    public static String a(String str) { return str; }
}

// with --deobf
package p000a.p001b;
/* renamed from: a.b.a */
public class C0000a {
    /* renamed from: a */ private static String f0a;
    /* renamed from: a */ public static String m0a(String str) { return str; }
}
```

The second is **harder** to read. Nothing was recovered.

What it buys is uniqueness: `m0a` is unique across the whole app where `a` is not, so
cross-referencing works, field/method collisions disappear, and — with `--deobf-cfg-file` persisting
the aliases in a `.jobf` file — names stay stable between runs, which is what makes diffing two app
versions produce signal instead of noise.

**Actual name recovery** comes from four other places:

1. `--use-source-name-as-class-name-alias always` — if the developer did not set
   `-renamesourcefileattribute`, the `SourceFile` attribute still says `LoginPresenter.java`.
2. A recovered R8 `mapping.txt` fed via `-Prename-mappings.format=PROGUARD_FILE`. If it shipped
   inside the APK, that is a finding in itself.
3. Kotlin's `@Metadata` annotation, which R8 does not strip by default and which carries original
   names — jadx's `kotlin-metadata` plugin reads it automatically.
4. You, renaming things by hand as you understand them, with F2 in the GUI, persisted with
   `--mappings-mode`.

---

### 5. Can the app's developer tell that I decompiled their APK?

**No.** Decompilation is a local, read-only operation on a file you already have. jadx opens the APK,
reads bytes, and writes files on your disk. It contacts nothing, phones nothing home, and writes no
marker back into the APK. There is no mechanism by which anyone could observe it.

What *is* observable is everything around it:

| Activity | Visible to the vendor? |
|---|---|
| Running jadx | **No** |
| Downloading the APK from Google Play | To Google, as an ordinary install |
| Running the app with Frida attached | **Often yes** — anti-instrumentation checks |
| Installing a re-signed, patched APK | Yes, if the app checks its signature |
| Sending modified requests to their API | **Yes. This is where you actually get noticed** |
| Fuzzing an endpoint | Loudly yes |

> **The legal question is separate and it is the one that matters.** "Undetectable" is not
> "permitted". Decompiling an application may be restricted by its licence, by contract, or by law
> depending on where you are and why you are doing it. Work under a scope agreement, a bug bounty
> programme's terms, or on software you own.

---

### 6. jadx vs apktool — which should I use?

Both, on the same APK, into two directories, at the same time.

| | jadx | apktool |
|---|---|---|
| Output | Java approximation + decoded resources | Smali + decoded resources + everything needed to rebuild |
| Readable at speed | **Yes** | No |
| Rebuilds into an installable APK | **No, never** | **Yes** |
| Faithful to the bytecode | Approximately | Exactly |
| Use for | Understanding | Changing |

The rule: **jadx to understand, apktool to change.** jadx's output is not designed to compile and
frequently will not — chapter §6.2's anonymous class emits `new Runnable(this)` for an interface, and
§4.1's enum switch emits `1.$SwitchMap$...`, an expression starting with a digit. Neither is a bug;
both are jadx choosing accuracy about the bytecode over syntactic validity.

`baksmali` is the third member of the family: Smali only, from a bare `.dex`, with the finest control
over disassembly. Use it when your DEX did not come from an APK — dumped from memory, extracted from
a packer, pulled out of a VDEX.

---

### 7. jadx opens but the code says `Method not decompiled` everywhere. Is the app protected?

Maybe. Read the **distribution**, not the total.

| Pattern | Diagnosis |
|---|---|
| Refusals spread thinly across many library packages | Normal. Kotlin default-argument constructors, generated JSON adapters, reflection internals |
| Refusals concentrated in the app's own security-relevant package | A control-flow obfuscator ran there. → [40](../40-Obfuscation/README.md) |
| Barely any classes at all, plus an `Application` subclass calling `System.loadLibrary` | A **packer**. The real DEX is loaded at runtime |
| One class with hundreds of warnings | Usually a giant generated dispatcher. Confirm, then skip |

On a real commercial app the refusals were 180 in an analytics SDK, 127 in Google's libraries, and 95
in the app's own 2,211 files — 4.3%, entirely benign, and inspection confirmed they were Kotlin
constructors with forty parameters.

```bash
# host — the diagnosis, not the total
grep -rl "Method not decompiled" out/sources | sed 's|out/sources/||; s|/[^/]*$||' \
  | cut -d/ -f1-3 | sort | uniq -c | sort -rn | head -20
```

---

### 8. Why does one app decompile into beautiful named code and another into `str2` and `iArr`?

**Debug information**, and it is a build flag, not obfuscation.

If the build used `javac -g` and `d8 --debug`, the DEX carries a `debug_info_item` recording the
original local variable names, and jadx applies them. Release builds strip it.

Measured on the same source (chapter §3.11):

```java
// d8 --release
public boolean unlock(char[] cArr) {
    boolean z = length == cArr2.length;
    int iMin = Math.min(cArr.length, cArr2.length);

// javac -g + d8 --debug
public boolean unlock(char[] candidate) {
    boolean equal = candidate.length == this.masterKey.length;
    int limit = Math.min(candidate.length, this.masterKey.length);
```

The second is character-for-character the source. The cost of the difference was 21 string-pool
entries and 536 bytes.

If you are seeing original names in a production APK, note it: it is a real (if minor) finding
(OWASP MASVS-CODE-4) and it means the rest of your engagement will go faster.

---

### 9. jadx output looks perfect but the app does not behave like it. What now?

Three possibilities, in decreasing order of likelihood:

1. **You are reading a path that does not execute.** Dead code, a feature flag, a branch reached only
   in another locale. jadx cannot tell you what runs. Hook it — [53-Frida](../53-Frida/README.md).
2. **The logic is not in the Java.** Look for `native` declarations, `System.loadLibrary`,
   `DexClassLoader`/`InMemoryDexClassLoader`, or a large high-entropy file in `assets/`.
   → [16-JNI](../16-JNI/README.md), [57-Ghidra](../57-Ghidra/README.md),
   [40 §3.5](../40-Obfuscation/README.md).
3. **jadx is wrong about that method.** Rare but real, and see question 10.

Work them in that order. Most of the time it is (1).

---

### 10. Can jadx produce Java that is simply wrong, with no warning?

**Yes, and this is the single most important thing in the chapter.**

Measured (chapter §6.6). A method accumulates into a register inside a `try`; the handler adds 100 to
whatever the accumulator holds. For input `{5}` the bytecode returns **105**. jadx printed:

```java
public static int accumulate(int[] iArr) {
    try {
        return 0 + iArr[0] + iArr[1];
    } catch (Exception e) {
        return 0 + 100;
    }
}
```

which returns **100**. No warning. No comment. Clean, idiomatic, compiling Java.

The cause is a readability transformation: `CodeShrinkVisitor` folds a value's definition into its
single use, which is sound unless something observes the intermediate value — and an exception edge
observes it.

The tell, if you are looking, is the leading `0 +`: a folded expression inside a `try` whose leading
term is a constant is the residue of an accumulator, and an accumulator inside a `try` is precisely
where a partial value can be observed.

The general statement, which does not depend on this specific case:

> jadx's correctness is a property of the **shape of the bytecode**, not of the semantics of the
> program. Compiler-produced bytecode is inside the envelope jadx is tuned for; obfuscator, packer,
> hand-patched and rewritten bytecode is not — and **the Java gives you no way to tell which case you
> are in.**

Which is why the rule is: find it in Java, confirm it in Smali, prove it at runtime.

---

### 11. What does `--show-bad-code` actually do? Everyone tells me to use it.

Everyone is roughly wrong. It replaces jadx's **complete instruction dump** with jadx's
**partially-reconstructed, known-incorrect Java**.

On a badly-failed method that is worse. Measured on a multi-entry loop (chapter §3.8):

```java
// default: a complete instruction dump, plus
throw new UnsupportedOperationException("Method not decompiled: ...");

// --show-bad-code:
public static int irreducible(int i, int i2) {
    int i3 = 0;
}
```

The second assigns zero to an unused local and falls off the end without returning. Skim past the
comment block and it reads as "this method does nothing".

Where it genuinely helps: a large method that mostly succeeded and failed on one branch, where the
partial output is 90% right and the dump would be 400 lines. Judge per method, and never use it as
your default reading mode for a method you intend to make a claim about.

---

### 12. `jadx` prints the help text but then hangs forever. What is wrong?

You are running the **GUI** launcher.

The Windows `jadx-gui` bundle installs `jadx.exe` plus `lib/jadx-gui-<ver>-all.jar` and nothing else.
That `jadx.exe` answers `--version` and `--help` from the command line, which makes it look like the
CLI, but any real invocation opens a window and blocks.

The CLI entry point is in the same jar:

```bash
# host
java -cp "C:\Program Files\jadx\lib\jadx-gui-1.5.3-all.jar" jadx.cli.JadxCLI -d out app.apk
```

Or download the full distribution from the project's releases page, which ships `bin/jadx` and
`bin/jadx.bat` alongside `jadx-gui`. Every script in this chapter auto-detects both layouts via a
`JADX` or `JADX_JAR` environment variable.

---

### 13. jadx runs out of memory / dies on a big app.

It is a JVM application decompiling tens of thousands of classes. In order of effectiveness:

```bash
# host
java -Xmx8g -cp jadx.jar jadx.cli.JadxCLI -j 4 --no-res --log-level error -d out huge.apk
```

- **Raise the heap.** `-Xmx8g`, which requires invoking `java` directly.
- **Lower the thread count.** `-j 4` or `-j 1`. Fewer threads, lower peak memory.
- **`--no-res`.** Resource decoding is a large chunk of memory on resource-heavy apps.
- **Use the GUI instead.** It decompiles lazily, one class at a time, and survives inputs the CLI
  cannot.

> **Watch for the silent partial run.** jadx catches per-class errors and continues, so a run that
> exits zero may still have produced far fewer files than there are classes. Compare
> `find out/sources -name '*.java' | wc -l` against
> `unzip -p app.apk classes.dex | dexdump - | grep -c "Class descriptor"` before concluding a class is
> absent. "The class is not there" and "jadx died before reaching it" look identical from the output.

---

### 14. I grepped the whole decompiled tree and found nothing. Can I report that the app does not do X?

Not yet. "I grepped and found nothing" is a statement about your grep. Before it becomes a finding of
absence you need five checks:

1. **Did the decompilation complete?** Class count in versus files out (question 13).
2. **What was refused?** A refused method's body is not in the Java, so your grep never saw it.
3. **Is code loaded dynamically?** `DexClassLoader`, `InMemoryDexClassLoader`, an encrypted asset.
4. **Is it native?** `native` declarations and `System.loadLibrary` mark the boundary.
5. **Do you have every split APK?** Code lives in splits, and pulling only `base.apk` is a very
   common and very expensive mistake.

Five commands. Chapter §6.10 lists everything jadx structurally cannot see.

---

### 15. What is that `str.hashCode();` line on its own before a `switch`?

It is **really in the bytecode**, and this one caught the author of this chapter out, which is why it
is written up in full.

The plausible story is that jadx left it behind while folding the compiler's two-stage string switch
back into one statement. `dexdump` says otherwise:

```
0000: invoke-virtual {v3}, Ljava/lang/String;.hashCode:()I     # result DISCARDED
0003: invoke-virtual {v3}, Ljava/lang/String;.hashCode:()I
0006: move-result v2
```

Two calls, the first with its result thrown away. `javac` emitted it: `switch` on a `null` String
must throw `NullPointerException`, so the compiler needs an unconditional dereference of the selector
before the lookup, and calling `hashCode()` and discarding the answer is the cheapest one available.
It survives `--no-restore-switch-over-string` for the same reason.

**The general lesson is better than the specific fact.** An unexplained statement in decompiled Java
has three possible authors — the developer, the compiler, the decompiler — and *guessing* between them
is how confident wrong statements get written down. One `dexdump` settles it in ten seconds.

While you are there: the `case` labels in a reconstructed string switch are in **hash order**, not
source order. Never infer intent from case ordering.

---

### 16. Why do the methods come out in a different order from the source?

No debug info means no line numbers, which means jadx has no ordering to sort by, so members come out
in DEX order — which `d8` sorts. In practice that is alphabetical, with nested classes hoisted.

Two consequences:

- A decompiled release class tells you **nothing** about how the author organised the file.
- Two versions of a class that look "reordered" between app releases may be byte-identical. Do not
  read meaning into it.

Build the same class with debug info and the members come back in source order (chapter §3.11).

---

### 17. Should I use jadx-gui or the command line?

Both, in alternation. Each has exactly one capability the other lacks.

**jadx-gui has cross-references.** Right-click → Find Usage answers "who calls this", resolved by
reference rather than by text. In an obfuscated app where four hundred methods are called `a`, that
is a question only the tool can answer, and it is usually the question you have. The GUI also
decompiles lazily, so it opens a 100 MB APK in seconds.

**The CLI produces files.** Files can be grepped, diffed between app versions, fed to other tools,
counted, ranked, committed to a case directory, and attached to a report.

Reading room and photocopier. You read in one and take copies from the other.

---

### 18. Can I recompile jadx's output and rebuild the app?

**No,** and it is not a goal jadx has. Two examples from this chapter's measured output that simply
do not compile:

```java
return new Runnable(this) { ... };          // Runnable is an interface; it has no constructor
switch (1.$SwitchMap$Foo[x.ordinal()]) {    // an expression cannot start with a digit
```

Both are jadx choosing to show the reality of the generated bytecode over producing valid syntax,
and both are the right call.

To change an app: `apktool d`, edit the Smali, `apktool b`, `zipalign`, `apksigner`. Chapter
[14 — Dalvik](../14-Dalvik/README.md) covers the whole round trip, including the two gates your
rebuilt APK has to pass and why a verifier rejection appears when a *screen* is opened rather than at
install time.

---

### 19. How do I turn what jadx shows me into a Frida hook?

Mechanically. Given

```java
private String buildAuthHeader(String userId, byte[] nonce, boolean refresh)
```

the hook is

```javascript
Java.use('com.example.auth.TokenManager')
    .buildAuthHeader.overload('java.lang.String', '[B', 'boolean')
    .implementation = function (userId, nonce, refresh) { ... };
```

The rules people get wrong:

| jadx shows | Frida wants |
|---|---|
| `String` | `'java.lang.String'` — fully qualified; jadx's imports are not part of the type |
| `byte[]` | `'[B'` |
| `String[]` | `'[Ljava.lang.String;'` |
| `Map<String, String>` | `'java.util.Map'` — **never include generics** |
| `Outer.Inner` | `'com.example.Outer$Inner'` — dollar, not dot |
| a `private` method | Exactly the same. Access modifiers do not constrain Frida |

Two jadx-specific traps: jadx may have **widened an access modifier** (it says so in a `JADX INFO`
comment), and if you ran with `--deobf` the class name in the output is a jadx **alias** —
`Java.use('C0000a')` will throw. The real name is in the `/* renamed from: */` comment.

---

### 20. If jadx is unreliable, why is it the first tool everyone reaches for?

Because "unreliable" is the wrong word, and the right framing is a cost-benefit one.

A mid-size app has 40,000–400,000 methods. As Smali that is millions of lines. Your actual job is to
find the handful of methods that matter, and reading assembly to find them is not a tractable use of
a week. jadx collapses that search by an order of magnitude in volume and rather more in cognitive
load: a 90-line Smali method is 9 lines of Java, and 9 lines can be skimmed. It also makes library
code *recognisable*, so you can skip the 90% of the tree that is somebody else's SDK.

It is right the overwhelming majority of the time, and when it is wrong it usually says so.

So: **jadx is a search accelerator with a comprehension bonus.** Use it for what it is superb at —
finding things — and spend ten minutes per finding confirming the ones that matter against the
bytecode. That is not distrust of the tool. That is knowing what kind of tool it is.
