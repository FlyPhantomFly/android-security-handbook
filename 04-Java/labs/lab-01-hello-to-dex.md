# Lab 01 — Hello World, from source to DEX and back again

> Part of [04 — Java](../README.md). Difficulty: beginner. No prior lab required.

---

## Objective

Follow one small Java class all the way down the Android toolchain and all the way back up, and
record exactly what information is destroyed at each step.

By the end you will be able to state, without guessing, which of these survive into a shipped APK:
class names, method names, field names, parameter names, local variable names, string literals,
comments, generic types, line numbers, and the difference between a compile-time constant and a
runtime field read.

This is the foundational lab of the chapter. Every later claim in this repository about "you can see
X in JADX" or "X is not recoverable" is a consequence of what you measure here.

---

## Prerequisites

- A JDK 17 or newer on your `PATH`. Check with `java -version` and `javac -version`.
- `d8` from the Android SDK build-tools. Install with the standalone `cmdline-tools` package if you
  do not want Android Studio: `sdkmanager "build-tools;34.0.0"`, then add
  `$ANDROID_HOME/build-tools/34.0.0` to your `PATH`.
- `jadx` and `baksmali` on your `PATH`. Both are single downloads, linked in
  [`../references/README.md`](../references/README.md).
- Comfort with a terminal, at the level of [02 — Linux Basics](../../02-Linux-Basics/README.md).

> **📖 Definition**
> **Toolchain** — the ordered set of programs that transform your source into the artefact that
> actually runs. Here the chain is `javac` (source to JVM bytecode), then `d8` (JVM bytecode to DEX),
> then packaging. Each program is a lossy transformation, and the losses are what this lab measures.

**Estimated time:** 45 to 60 minutes.

---

## Setup

Create a clean working directory. Everything in this lab happens on the host; nothing touches a
device.

```bash
# host
mkdir -p ~/lab01-hello && cd ~/lab01-hello
```

Create `Hello.java` with exactly this content. The class is deliberately small but contains one of
each thing we want to track: a compile-time constant, an instance field, a constructor, an instance
method, string concatenation, and a counted loop.

```java
// host — save as ~/lab01-hello/Hello.java
public class Hello {

    private static final String GREETING = "Hello, DEX!";

    private final String name;

    public Hello(String name) {
        this.name = name;
    }

    public String greet() {
        return GREETING + " " + this.name;
    }

    public static void main(String[] args) {
        Hello h = new Hello("reverser");
        System.out.println(h.greet());
        int sum = 0;
        for (int i = 0; i < 5; i++) {
            sum += i;
        }
        System.out.println("sum=" + sum);
    }
}
```

---

## Steps

### Step 1 — Compile and run

```bash
# host
javac -g Hello.java
java Hello
```

The `-g` flag tells `javac` to keep debug information: local variable names, parameter names, and a
line number table. Most real builds are compiled with some form of `-g`, so this is the realistic
case. You will remove it later and measure the difference.

Expected output:

```
Hello, DEX! reverser
sum=10
```

You now have `Hello.class`. Confirm the file's identity from its first four bytes.

```bash
# host — Linux and macOS
xxd Hello.class | head -1
```

```
00000000: cafe babe 0000 0044 004d 0a00 0200 0300  .......D.M......
```

The `cafebabe` magic identifies a JVM class file. The `0044` that follows is the major version, `68`
in decimal, which is Java 24. Yours will differ with your JDK version, and that is itself a useful
fingerprint when you meet an unknown `.class` file in the field.

### Step 2 — Read the bytecode with `javap`

`javap` is a JDK tool, so you already have it. It is the only disassembler you need for JVM bytecode.

```bash
# host
javap -c -p Hello.class
```

Expected output, trimmed to the interesting parts:

```
public class Hello {
  private static final java.lang.String GREETING;

  private final java.lang.String name;

  public Hello(java.lang.String);
    Code:
       0: aload_0
       1: invokespecial #1                  // Method java/lang/Object."<init>":()V
       4: aload_0
       5: aload_1
       6: putfield      #7                  // Field name:Ljava/lang/String;
       9: return

  public java.lang.String greet();
    Code:
       0: aload_0
       1: getfield      #7                  // Field name:Ljava/lang/String;
       4: invokedynamic #13,  0             // InvokeDynamic #0:makeConcatWithConstants:(Ljava/lang/String;)Ljava/lang/String;
       9: areturn

  public static void main(java.lang.String[]);
    Code:
       0: new           #8                  // class Hello
       3: dup
       4: ldc           #17                 // String reverser
       6: invokespecial #19                 // Method "<init>":(Ljava/lang/String;)V
       9: astore_1
      10: getstatic     #22                 // Field java/lang/System.out:Ljava/io/PrintStream;
      13: aload_1
      14: invokevirtual #28                 // Method greet:()Ljava/lang/String;
      17: invokevirtual #32                 // Method java/io/PrintStream.println:(Ljava/lang/String;)V
      20: iconst_0
      21: istore_2
      22: iconst_0
      23: istore_3
      24: iload_3
      25: iconst_5
      26: if_icmpge     39
      29: iload_2
      30: iload_3
      31: iadd
      32: istore_2
      33: iinc          3, 1
      36: goto          24
      39: getstatic     #22                 // Field java/lang/System.out:Ljava/io/PrintStream;
      42: iload_2
      43: invokedynamic #37,  0             // InvokeDynamic #1:makeConcatWithConstants:(I)Ljava/lang/String;
      48: invokevirtual #32                 // Method java/io/PrintStream.println:(Ljava/lang/String;)V
      51: return
}
```

Read the constructor first, because it shows the single most important structural fact about Java.
The instruction at offset 1 is `invokespecial java/lang/Object."<init>":()V`. You never wrote that
call. The compiler inserted it, because every constructor must first initialise its superclass, and
`Hello` implicitly extends `Object`. The `<init>` name is not a name you can type in Java; it is the
internal name the JVM gives every constructor.

Now read `main` from offset 20 onward. There is no `for` loop in the bytecode. There is a counter
initialised to zero, a comparison, a conditional forward jump, and an unconditional backward `goto`.
Every loop form in Java — `for`, `while`, `do-while`, enhanced `for` over an array — compiles to some
arrangement of exactly those pieces. This is why a decompiler must *guess* which loop you wrote.

> **🧠 Mental Model**
> The JVM is a stack machine. `aload_0` pushes local variable 0 (which is `this` in an instance
> method) onto an operand stack; `getfield` pops an object reference and pushes a field value;
> `invokevirtual` pops the receiver and arguments and pushes the return value. DEX, which you will
> see in step 4, is a register machine instead, so the same logic appears with named registers and
> no pushing.

### Step 3 — Read the constant pool

```bash
# host
javap -v -p Hello.class
```

This is much longer. Find these three things in the output.

First, the constant pool entry for the field `GREETING`:

```
  #40 = Utf8               GREETING
  #41 = Utf8               ConstantValue
  #42 = String             #43            // Hello, DEX!
  #43 = Utf8               Hello, DEX!
```

Second, near the end of the file, the bootstrap method table for the two `invokedynamic`
instructions:

```
BootstrapMethods:
  0: #65 invokestatic java/lang/invoke/StringConcatFactory.makeConcatWithConstants:(...)
    Method arguments:
      #61 Hello, DEX!
  1: #65 invokestatic java/lang/invoke/StringConcatFactory.makeConcatWithConstants:(...)
    Method arguments:
      #63 sum=
```

Third, the field declaration itself:

```
  private static final java.lang.String GREETING;
    descriptor: Ljava/lang/String;
    flags: ACC_PRIVATE, ACC_STATIC, ACC_FINAL
    ConstantValue: String Hello, DEX!
```

Something important is visible here that most people never notice. The literal `Hello, DEX!` appears
in the constant pool **twice**, as two distinct entries: once as the `ConstantValue` of the field, and
once — with a trailing space, because the compiler merged the `+ " "` into it — as the bootstrap
argument inside `greet()`. The `greet()` method never reads the `GREETING` field at all. There is no
`getstatic` for it anywhere in the bytecode.

> **🔬 Under the Hood**
> A `static final` field of primitive or `String` type initialised with a compile-time constant
> expression is a **compile-time constant**. The JLS requires the compiler to inline its value at
> every use site. The field is still emitted, so reflection and other classes compiled separately can
> find it, but no code reads it.

> **⚠️ Warning**
> This is why "I changed the constant and rebuilt only that one file, but the old value is still
> being used" happens, and it is why storing a secret in a `private static final String` is worse
> than storing it in a plain field: the value is not in one place you can find and audit, it is
> copied into every class that referenced it.

### Step 4 — Convert to DEX

```bash
# host
d8 --min-api 21 Hello.class --output .
ls -l classes.dex
xxd classes.dex | head -1
```

Expected first line of the hex dump:

```
00000000: 6465 780a 3033 3500 ....
```

Those eight bytes decode as the ASCII text `dex`, a newline, `035`, and a NUL. That is the DEX magic
and version, and it is the first thing [`../scripts/dump-strings.py`](../scripts/dump-strings.py)
checks. Your version digits may read `038`, `039`, or higher depending on your `--min-api`.

### Step 5 — Disassemble the DEX

```bash
# host
baksmali d classes.dex -o smali_out
cat smali_out/Hello.smali
```

Your exact register numbers and instruction order depend on your `d8` version, so treat the listing
below as representative rather than byte-identical. The constructor looks like this:

```smali
# baksmali output — smali_out/Hello.smali
.method public constructor <init>(Ljava/lang/String;)V
    .registers 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, LHello;->name:Ljava/lang/String;

    return-void
.end method
```

Compare that line by line with the `javap` constructor from step 2. Same three logical operations,
completely different shape. There is no stack. `p0` is the receiver register, holding `this`; `p1` is
the first parameter. `invoke-direct` is the DEX opcode for a non-virtual call, which covers both
constructors and `private` methods. `iput-object` writes an object-typed instance field, and it names
the field completely: owner type, field name, and field descriptor, all in one instruction.

The `greet()` method typically appears as follows, because `d8` **desugars** the `invokedynamic`
string concatenation back into explicit `StringBuilder` calls:

```smali
# baksmali output — representative
.method public greet()Ljava/lang/String;
    .registers 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Hello, DEX! "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, LHello;->name:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
```

> **📖 Definition**
> **Desugaring** — rewriting a language or bytecode feature into an equivalent built from older,
> more widely supported constructs. `d8` desugars `invokedynamic` string concatenation, lambdas,
> default interface methods, and parts of the modern `java.time` and stream APIs, so that code
> compiled against a new JDK still runs on old Android versions.

If you built with a high `--min-api`, you may instead see an `invoke-custom` instruction referring to
`StringConcatFactory`. Both forms are correct; which one you get depends on your `d8` version and
`--min-api`. Note which one you got, because the `StringBuilder` form is what you will meet in the
overwhelming majority of real APKs.

Now grep the whole disassembly for our two literals.

```bash
# host
grep -rn "Hello, DEX" smali_out/
```

You will find the concatenation literal. Note that `GREETING`'s field value does not appear as a
`sget-object` read anywhere, for exactly the compile-time constant reason from step 3.

### Step 6 — Decompile with JADX and diff against your source

```bash
# host
jadx -d jadx_out classes.dex
cat jadx_out/sources/Hello.java
```

You should get something very close to this:

```java
// jadx output — jadx_out/sources/Hello.java
public class Hello {
    private static final String GREETING = "Hello, DEX!";
    private final String name;

    public Hello(String name) {
        this.name = name;
    }

    public String greet() {
        return "Hello, DEX! " + this.name;
    }

    public static void main(String[] args) {
        Hello h = new Hello("reverser");
        System.out.println(h.greet());
        int sum = 0;
        for (int i = 0; i < 5; i++) {
            sum += i;
        }
        System.out.println("sum=" + sum);
    }
}
```

Now diff it against what you wrote and be precise about the differences. The important one is in
`greet()`: your source read a named constant, and the decompiled source shows an inlined literal. The
name `GREETING` still exists as a field declaration, but the *link* between the use and the
declaration is gone forever. No decompiler can restore it, because the information was destroyed by
`javac`, not by any obfuscator.

### Step 7 — Measure what debug information buys you

Repeat the whole pipeline without `-g`.

```bash
# host
mkdir -p nodebug && cd nodebug
cp ../Hello.java .
javac -g:none Hello.java
d8 --min-api 21 Hello.class --output .
jadx -d jadx_out classes.dex
cat jadx_out/sources/Hello.java
cd ..
```

Compare the two decompiled files. With `-g:none` the local variables `h`, `sum`, and `i` become
generated names such as `hello`, `i`, `i2`, and the parameter of the constructor loses its original
name. JADX invents plausible names from the types. Field and method names are unaffected, because
those are not debug information — they are part of the class structure and are needed for linking.

```bash
# host
diff jadx_out/sources/Hello.java nodebug/jadx_out/sources/Hello.java
```

### Step 8 — Fill in the survival table

This is the deliverable of the lab. Fill it in from your own observations, then check it against the
solution.

| Artefact | In `.java` | In `.class` | In `.dex` | Recovered by JADX |
|---|---|---|---|---|
| Class name `Hello` | | | | |
| Method name `greet` | | | | |
| Field name `name` | | | | |
| Constructor parameter name `name` | | | | |
| Local variable name `sum` | | | | |
| String literal `reverser` | | | | |
| Value of `GREETING` | | | | |
| Link from `greet()` to the `GREETING` field | | | | |
| The comment you would have written above `main` | | | | |
| The fact that the loop was a `for` and not a `while` | | | | |
| Line numbers | | | | |

---

## Hints

<details>
<summary>Hint 1 — `d8: command not found`</summary>

`d8` lives in the Android SDK build-tools directory, not in the SDK root. Find it with
`find "$ANDROID_HOME" -name 'd8*' -type f`. On Windows it is `d8.bat`. If you have no SDK at all,
install just the command-line tools, then run
`sdkmanager --install "build-tools;34.0.0"`.
</details>

<details>
<summary>Hint 2 — `d8` complains about a missing `android.jar`</summary>

Pass the platform jar explicitly:
`d8 --lib "$ANDROID_HOME/platforms/android-34/android.jar" --min-api 21 Hello.class --output .`
For a class that only touches `java.lang`, this is usually unnecessary, but some `d8` versions insist.
</details>

<details>
<summary>Hint 3 — `xxd` does not exist on my system</summary>

Use `od -A x -t x1z -N 16 classes.dex` on any Unix, or on Windows use PowerShell:
`Format-Hex -Path classes.dex -Count 16`. On Windows, note that `strings` is the Sysinternals tool and
behaves differently from the Unix one; prefer
[`../scripts/dump-strings.py`](../scripts/dump-strings.py), which is cross-platform and parses the
string table properly instead of scanning for printable runs.
</details>

<details>
<summary>Hint 4 — my `greet()` shows `invoke-custom` instead of `StringBuilder`</summary>

That is fine and expected on newer `d8` with a high `--min-api`. Re-run with `--min-api 21` to force
the desugared form, then compare the two. Seeing both is better learning than seeing either alone.
</details>

<details>
<summary>Hint 5 — JADX output differs slightly from the listing above</summary>

Decompiler output is version-dependent. What matters is not textual identity but the two structural
observations: the `GREETING` reference became an inlined literal, and the loop was reconstructed as a
`for`. If both are true in your output, you have the right result.
</details>

---

## Success criteria

You have completed this lab when all of the following are true.

1. You can produce `Hello.class`, `classes.dex`, and a JADX-decompiled `Hello.java` from the original
   source, and the decompiled program still prints `Hello, DEX! reverser` and `sum=10` when
   recompiled and run.
2. You can point at the exact byte offsets of the `cafebabe` and `dex\n035\0` magic values in your two
   binaries.
3. You can explain, in one sentence and without hedging, why `greet()` in the decompiled output
   contains a string literal rather than a reference to `GREETING`.
4. You can name three things in the survival table that are permanently destroyed by `javac`, before
   any Android tool or obfuscator runs.
5. You can read the eight-instruction `<init>` Smali listing and say which instruction corresponds to
   which line of your Java constructor, including the one line you did not write.

---

## Solution

<details>
<summary>Click to reveal the completed survival table and the reasoning</summary>

### Completed survival table

| Artefact | In `.java` | In `.class` | In `.dex` | Recovered by JADX |
|---|---|---|---|---|
| Class name `Hello` | yes | yes | yes | yes |
| Method name `greet` | yes | yes | yes | yes |
| Field name `name` | yes | yes | yes | yes |
| Constructor parameter name `name` | yes | only with `-g` or `-parameters` | only if the `.class` had it | yes with `-g`, invented without |
| Local variable name `sum` | yes | only with `-g` | only if the `.class` had it | yes with `-g`, invented without |
| String literal `reverser` | yes | yes, constant pool | yes, string table | yes |
| Value of `GREETING` | yes | yes, twice — `ConstantValue` and bootstrap argument | yes, as a `const-string` | yes, but as a literal |
| Link from `greet()` to the `GREETING` field | yes | **no** | no | no |
| Comments | yes | **no** | no | no |
| Loop was `for` not `while` | yes | **no** | no | reconstructed as a plausible guess |
| Line numbers | implicit | only with `-g` | only if the `.class` had it | shown as JADX comments when present |

### The three permanent losses caused by `javac`, before Android is involved

1. **Comments and formatting.** Discarded by the lexer. Nothing downstream can recover them.
2. **The identity of a compile-time constant use.** `GREETING + " "` became the single literal
   `"Hello, DEX! "` at compile time. The reference is not obfuscated, it does not exist.
3. **Which loop syntax was used, and which of several equivalent expression forms was written.**
   `for`, `while`, and a manual `goto`-free rewrite all produce the same comparison-and-branch shape.

Everything else on the list is either structurally required (class, method, and field names are needed
for linking, so they always survive unless an obfuscator renames them) or is optional debug metadata
that survives only if `-g` was used.

### Annotated `<init>` mapping

```smali
.method public constructor <init>(Ljava/lang/String;)V
    .registers 2
    #                      ^ two registers: p0 = this, p1 = the String parameter

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    #  <-- the implicit super() call you never wrote. Java requires that the
    #      superclass constructor runs first; javac inserts it.

    iput-object p1, p0, LHello;->name:Ljava/lang/String;
    #  <-- this.name = name;
    #      iput = instance field write, -object because the type is a reference.
    #      Source register p1, target object p0, then the fully qualified field.

    return-void
    #  <-- the implicit return at the end of a void method.
.end method
```

Note that `.registers 2` counts parameter registers too. Registers are allocated at the *end* of the
frame for parameters, which is why baksmali can name them `p0` and `p1` instead of `v0` and `v1`.

### Why `greet()` shows a literal

The JLS classifies `private static final String GREETING = "Hello, DEX!"` as a compile-time constant
because the initialiser is a constant expression of type `String`. The specification then requires
that every *use* of a compile-time constant be replaced by its value during compilation. So by the
time `javac` has finished, `greet()` no longer refers to the field at all; it refers to a literal in
the constant pool. `d8` and JADX faithfully carry forward what they were given. The field survives as
a declaration only because other separately compiled classes and reflection might look for it.

### Practical consequence to carry into the rest of the chapter

Every hardcoded secret in a real app is subject to exactly this mechanism. If a developer writes
`private static final String API_KEY = "sk_live_...."` and uses it in four classes, the string is
duplicated into all four classes' constant pools, merged into the shared DEX string table, and is
findable with a single `grep`. Marking it `private` changed nothing; marking it `static final` made
it worse. That is the finding you will write up over and over, and lab 2 is where you practise
finding it.

</details>

---

## Next

Continue to [Lab 02 — Strings, `==`, and the DEX string table](lab-02-string-and-equals.md), which
takes the string-table observation from step 5 and turns it into a real vulnerability.
