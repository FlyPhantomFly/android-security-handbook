# Example 01 — Source to DEX to Java: exactly what was lost

A source → DEX → decompiled-Java triple, built and measured on the machine that wrote
chapter [56](../../README.md). Every listing here is captured output, not an illustration.

| File | What it is |
|---|---|
| [`AccountVault.java`](AccountVault.java) | The source. Ordinary Java: generics, a `switch` over `String`, try-with-resources, varargs, an anonymous class, an enum, a nested class |
| [`build.sh`](build.sh) | `javac` → `d8` → `jadx`, twice: once release, once debug. Builds outside the repository |
| [`decompiled-release.java`](decompiled-release.java) | jadx 1.5.3 output for `javac -g:none` + `d8 --release` — what a shipped app looks like |
| [`decompiled-debug.java`](decompiled-debug.java) | jadx 1.5.3 output for `javac -g` + `d8 --debug` — what a debuggable build looks like |

```bash
# host
export JADX_JAR="C:/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar"   # or leave unset if jadx is on PATH
./build.sh
```

---

## The measurements

Taken on this machine with JDK 24, build-tools 35.0.1, `android-35`'s `android.jar`, jadx 1.5.3.

| | release | debug |
|---|---|---|
| `classes.dex` size | 5,568 bytes | 6,104 bytes |
| `string_ids_size` | 121 | 142 |
| The identifier `candidate` in the string pool | **0** | **1** |
| The identifier `equal` in the string pool | **0** | **1** |
| The identifier `limit` in the string pool | **0** | **1** |

Twenty-one extra string-pool entries, 536 extra bytes, and the difference between reading
`boolean z` and reading `boolean equal`.

The captured `decompiled-*.java` files in this directory were verified byte-identical to a fresh
`./build.sh` run, apart from the `/* loaded from: */` header comment that records the absolute path
of the DEX.

---

## What was lost, by category

### 1. Comments and formatting — gone at `javac`, unrecoverable

The source has Javadoc on five methods. None of it exists in any compiled artefact. No decompiler
will ever recover it.

### 2. Generic type arguments — partly gone

```java
// source
private final Map<String, List<String>> rolesByAccount = new HashMap<String, List<String>>();

// decompiled (both builds)
private final Map<String, List<String>> rolesByAccount = new HashMap();
```

The **declaration**'s generic type survived, because `javac` emits a `Signature` attribute for it and
`d8` carries that into the DEX. The **allocation**'s did not, because a `new` expression never had a
signature to begin with. This is not jadx being inconsistent — it is jadx reporting exactly what is
and is not in the file.

In the debug build the local gets its diamond back — `List<String> visible = new ArrayList<>();` —
because the debug info records the declared type of the local.

### 3. Local variable names — the headline

```java
// release
public boolean unlock(char[] cArr) {
    int length = cArr.length;
    char[] cArr2 = this.masterKey;
    boolean z = length == cArr2.length;
    int iMin = Math.min(cArr.length, cArr2.length);

// debug
public boolean unlock(char[] candidate) {
    boolean equal = candidate.length == this.masterKey.length;
    int limit = Math.min(candidate.length, this.masterKey.length);
```

The debug version is character-for-character the source apart from `this.` qualification.

Note `iMin` in the release build: jadx named an `int` after the method that produced it (`Math.min`).
That is a genuinely helpful heuristic and it is entirely invented — the variable was called `limit`.

### 4. Character literals — inference cannot recover them

```java
// source
while ((b = in.read()) != -1 && b != '\n') {

// decompiled (both builds)
if (i == -1 || i == 10) {
```

`'\n'` is `char` 10, and the comparison is against the `int` returned by `read()`. There is no
surviving evidence anywhere in the DEX that the author wrote a character literal.

### 5. Member ordering — not preserved in release builds

The release build lists methods **alphabetically** (`auditor`, `describe`, `readHeader`, `rolesFor`,
`tierFromPlanName`, `tokenOf`, `unlock`) with the nested classes hoisted to the top. The debug build
lists them in source order, because line numbers give jadx an ordering to sort by.

So the order of members in a decompiled release class tells you nothing about how the author organised
the file — and two classes that appear "reordered" between two versions of an app may be identical.

### 6. Syntactic sugar — expanded and not re-folded

`try`-with-resources becomes an explicit `try`/`catch (Throwable th)` with a nested `close()` and
`addSuppressed`. All of that machinery is real and `javac` wrote it; the source had one line.

### 7. Compile-time constants — inlined at their use sites

```java
// source
String out = ENDPOINT + "?acct=" + accountId + "&lane=" + label;

// decompiled
String str2 = "https://api.example.invalid/v3/session?acct=" + str + "&lane=" + ...
```

`ENDPOINT` is a `static final String` initialised with a literal, so `javac` substituted its *value*.
Meanwhile `MAX_ATTEMPTS` — also a compile-time constant — came back as a *name*, because jadx matched
the literal `3` back to the field. Same language feature, opposite-looking results.

That second one is a guess. `--no-replace-consts` shows you the literal.

### 8. The anonymous class — output that does not compile

```java
return new Runnable(this) { // from class: com.pentest.ch56.AccountVault.1
    final /* synthetic */ AccountVault this$0;
    { this.this$0 = this; }
    ...
```

`Runnable` is an interface and has no constructor. This will not compile. jadx is showing the reality
of the generated class `AccountVault$1`, which *does* take the outer instance and *does* store it in
a synthetic field. Meanwhile the captured `tags` array is shown as a plain reference, even though in
the bytecode it is a synthetic `val$tags` field — jadx undid that capture for readability.

Maximally literal about one synthetic member, maximally helpful about another, in one construct.

---

## The result nobody expects

**`tierFromPlanName` decompiles cleanly in the release build and is REFUSED in the debug build.**

Release:

```java
public Tier tierFromPlanName(String str) {
    str.hashCode();
    switch (str) {
        case "enterprise": return Tier.ENTERPRISE;
        case "free":       return Tier.FREE;
        case "plus":       return Tier.PLUS;
        default: throw new IllegalArgumentException("unknown plan: " + str);
    }
}
```

Debug:

```
/* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
/* JADX WARN: Removed duplicated region for block: B:14:0x0026  */
/*
    Code decompiled incorrectly, please refer to instructions dump.
*/
... throw new UnsupportedOperationException("Method not decompiled: ...")
```

Two lessons, and the second is the important one.

**First**, the debug build's instruction dump shows you what the release build's tidy `switch (str)` is
a *reconstruction of*: `hashCode()` into a lookup switch, an `equals()` confirmation per candidate, a
synthesised dense index, and a second switch on that index. `SwitchOverStringVisitor` folds all of
that back into one statement in the release build. And the case order — enterprise, free, plus — is
**hash order**, not source order.

The release build's stray `str.hashCode();` is *not* part of that reconstruction, which is a trap
worth knowing. `dexdump` shows **two** `invoke-virtual hashCode` instructions in the method, the first
with its result discarded — `javac` emits it as the implicit null check that makes `switch (null)`
throw `NullPointerException`. jadx printed it because it is there. It survives
`--no-restore-switch-over-string` for the same reason. The line that looks most like a decompiler
artefact is the most faithful line in the method, and only the bytecode tells you that.

**Second**, and this is why the example is in the chapter: *more information made the output worse for
one method.* The line-number table constrains how jadx may duplicate and reorder blocks, and the
string-switch reconstruction needs exactly that freedom. "Build with debug info and jadx does better"
is true on average and false per method.

Which is the whole discipline in one sentence: **statements about a decompiler that are true on
average are not true about the method you are looking at.** Check the method.

---

## What this example does not show

- **R8.** A real release build runs R8, which renames, inlines, merges and rewrites. Everything above
  happens *before* any of that. See chapter 42 (R8) and
  [40-Obfuscation](../../../40-Obfuscation/README.md).
- **Kotlin.** Every artefact here is a Java one. See
  [05-Kotlin §6.1](../../../05-Kotlin/README.md#61-the-master-fingerprint-table).
- **jadx being wrong.** Everything here is accurate output, faithfully reporting what is in the file.
  For the other half, see [example 02](../02-when-jadx-is-wrong/README.md).
