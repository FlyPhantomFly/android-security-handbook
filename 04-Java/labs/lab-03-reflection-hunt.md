# Lab 03 — Reflection hunt (CTF)

> Part of [04 — Java](../README.md). Difficulty: intermediate. CTF-style.
> Prerequisite labs: [Lab 01](lab-01-hello-to-dex.md) and [Lab 02](lab-02-string-and-equals.md).

---

## Objective

You are given a compiled application that calls a method you cannot see. The class name is not in the
string table. The method name is not in the string table. The value the method returns is not in the
string table either. Every technique from Lab 02 fails.

Recover the hidden call **statically**, from disassembly alone, then confirm it **dynamically**, and
extract the flag.

This is the shape of a real malware triage. The specific tricks used here — a Base64-encoded class
name, a method name built by character arithmetic, and a payload assembled at runtime — are the three
most common cheap obfuscations you will meet, and all three fail against the same fixed workflow.

> **📖 Definition**
> **Reflection** — the ability of a running program to inspect and manipulate its own structure:
> to look up a class by its name as a string, to find a method by its name as a string, and to call
> that method without the call ever appearing as a normal method invocation in the bytecode. Because
> the target is named by a *value* rather than by a *symbol*, static analysis cannot follow the call
> without first working out what that value is.

**Estimated time:** 60 to 90 minutes.

---

## Prerequisites

- A JDK 17 or newer.
- `d8`, `baksmali`, and `jadx` on your `PATH`, as in Lab 01.
- Python 3.8+ for [`../scripts/dump-strings.py`](../scripts/dump-strings.py).
- Optional but recommended for the dynamic phase: Frida, covered fully in
  [53 — Frida](../../53-Frida/README.md). The lab provides a JVM-only alternative so you can complete
  it with nothing but a JDK.

---

## Setup

```bash
# host
mkdir -p ~/lab03-vault && cd ~/lab03-vault
```

Create `VaultChallenge.java` with exactly this content. Two classes in one file is legal Java as long
as only one of them is `public`, and it keeps the challenge to a single copy-paste.

```java
// host — save as ~/lab03-vault/VaultChallenge.java
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class VaultChallenge {

    private static String className() {
        return new String(Base64.getDecoder().decode("U2VjcmV0VmF1bHQ="),
                          StandardCharsets.UTF_8);
    }

    private static String methodName() {
        char[] c = { 't', 'm', 'k', 'n', 'b', 'j' };
        for (int i = 0; i < c.length; i++) {
            c[i] = (char) (c[i] + 1);
        }
        return new String(c);
    }

    public static void main(String[] args) {
        try {
            Class<?> target = Class.forName(className());
            Method m = target.getDeclaredMethod(methodName(), int.class);
            m.setAccessible(true);
            Object result = m.invoke(null, 0x5eed);
            System.out.println("vault says: " + result);
        } catch (Exception e) {
            System.out.println("vault locked");
        }
    }
}

class SecretVault {

    private static final byte[] SEALED = {
            (byte) 0xab, (byte) 0xa1, (byte) 0xac, (byte) 0xaa, (byte) 0x96, (byte) 0x9f, (byte) 0xde,
            (byte) 0x8b, (byte) 0x81, (byte) 0xde, (byte) 0x8e, (byte) 0x99, (byte) 0xdc, (byte) 0xdd,
            (byte) 0x83, (byte) 0xb2, (byte) 0xdc, (byte) 0x9e, (byte) 0xb2, (byte) 0x83, (byte) 0xdd,
            (byte) 0x99, (byte) 0xb2, (byte) 0xdd, (byte) 0x8f, (byte) 0x8b, (byte) 0x98, (byte) 0x9e,
            (byte) 0x8e, (byte) 0xd9, (byte) 0x99, (byte) 0xdc, (byte) 0xdd, (byte) 0x83, (byte) 0x90
    };

    private static String unlock(int seed) {
        byte key = (byte) (seed & 0xFF);
        byte[] out = new byte[SEALED.length];
        for (int i = 0; i < SEALED.length; i++) {
            out[i] = (byte) (SEALED[i] ^ key);
        }
        return new String(out, StandardCharsets.UTF_8);
    }
}
```

Build the challenge artefacts and then **delete the source**, so you are working the way you would on
a real engagement.

```bash
# host
javac -g:none VaultChallenge.java
d8 --min-api 21 VaultChallenge.class SecretVault.class --output .
mkdir -p keep && mv VaultChallenge.java keep/     # move it out of sight; do not read it again
ls
```

You should now have `VaultChallenge.class`, `SecretVault.class`, and `classes.dex`. From here on,
pretend `keep/` does not exist until you have the flag.

> **⚠️ Warning**
> Do not run the program yet. The first half of this lab is deliberately static-only. Getting the
> answer by running the binary is the easy path, and it is the path that is unavailable to you when
> the target only executes its payload on a specific device, after a specific date, or when it
> decides it is not being watched. Earn the static answer first.

---

## Steps

### Step 1 — Establish that the easy techniques fail

Run the Lab 02 playbook and watch it come up empty.

```bash
# host
python3 ../04-Java/scripts/dump-strings.py classes.dex --min-len 4
```

Search that output for the words you would expect. There is no `SecretVault`. There is no `unlock`
as a *literal*. There is no flag text.

```bash
# host
python3 ../04-Java/scripts/dump-strings.py classes.dex --min-len 4 | grep -Ei 'vault|unlock|flag'
```

The only interesting things you get back are `VaultChallenge`, `vault says: `, and `vault locked`,
which are the log messages, plus one string that should catch your eye immediately if you run the
heuristic mode:

```bash
# host
python3 ../04-Java/scripts/dump-strings.py classes.dex --min-len 4 --heuristic
```

> **🧠 Mental Model**
> A class name that does not appear in the type table but is clearly being loaded means the name is
> computed. A method name that does not appear as a literal but is clearly being looked up means the
> name is computed. In both cases your job changes from *searching* to *evaluating*: you now have to
> execute, by hand or by machine, the small piece of code that produces the name.

### Step 2 — Grep for the reflection fingerprints

```bash
# host
baksmali d classes.dex -o smali_out
bash ../04-Java/scripts/find-reflection.sh --smali smali_out
```

Or by hand, which is what the script automates:

```bash
# host
grep -rn 'Ljava/lang/Class;->forName' smali_out/
grep -rn 'getDeclaredMethod\|getDeclaredField\|getMethod(' smali_out/
grep -rn 'setAccessible' smali_out/
grep -rn 'Ljava/lang/reflect/Method;->invoke' smali_out/
grep -rn 'Base64' smali_out/
```

All five hit, and all five hit inside `VaultChallenge`. That co-location is itself the signal: an app
that legitimately uses reflection for a compatibility shim calls `forName` with a literal and does not
need `setAccessible`. An app that calls `forName` on a computed name, immediately looks up a method by
a computed name, immediately disables the access check, and immediately invokes it, is hiding
something on purpose.

### Step 3 — Read the Smali fingerprint

```bash
# host
sed -n '/method public static main/,/end method/p' smali_out/VaultChallenge.smali
```

Your output will be close to the following. Register numbers and label names vary between `d8`
versions, so match on the *shape*, not on the text.

```smali
# baksmali output — representative
.method public static main([Ljava/lang/String;)V
    .registers 6

    :try_start_0
    invoke-static {}, LVaultChallenge;->className()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    #  ^^^ the argument is NOT a const-string. Trace v0 backwards.

    move-result-object v0

    invoke-static {}, LVaultChallenge;->methodName()Ljava/lang/String;

    move-result-object v1

    const/4 v2, 0x1

    new-array v3, v2, [Ljava/lang/Class;

    const/4 v4, 0x0

    sget-object v5, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;
    #  ^^^ Integer.TYPE is int.class — so the hidden method takes one int parameter.

    aput-object v5, v3, v4

    invoke-virtual {v0, v1, v3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    invoke-virtual {v0, v2}, Ljava/lang/reflect/Method;->setAccessible(Z)V
    #  ^^^ v2 still holds 0x1, so this is setAccessible(true).

    const v1, 0x5eed
    #  ^^^ the single int argument, 24301 decimal.

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    ...

    invoke-virtual {v0, v4, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    #  ^^^ v4 is 0x0, i.e. a null receiver, so the hidden method is static.

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
.end method
```

Before decoding anything, write down everything the *call site alone* tells you. This is the habit
that matters, because on a real target you often cannot decode the name and must proceed on shape
alone.

| Observation in Smali | What it proves about the hidden method |
|---|---|
| `Integer.TYPE` placed in the `Class[]` | It takes exactly one parameter, of primitive type `int` |
| `null` (register holding `0x0`) passed as the `invoke` receiver | It is `static` |
| `getDeclaredMethod`, not `getMethod` | It is not `public`, or the author assumed it was not |
| `setAccessible(true)` present | The access check would otherwise have failed, confirming non-public |
| `const v1, 0x5eed` as the sole argument | The argument is a fixed constant, 24301, not user input |
| Return value flows straight into `println` | It returns something printable, most likely a `String` |
| Whole sequence wrapped in `.catch Ljava/lang/Exception;` | Failure is silent by design |

### Step 4 — Recover the class name

Trace the register feeding `forName`. It comes from `className()`. Read that method.

```bash
# host
sed -n '/method private static className/,/end method/p' smali_out/VaultChallenge.smali
```

You will see a `const-string` holding a Base64-looking value, passed to
`Ljava/util/Base64$Decoder;->decode(Ljava/lang/String;)[B`, whose result is handed to a `String`
constructor. That is a decode-then-use pipeline, and you can evaluate it by hand.

```bash
# host
echo -n 'U2VjcmV0VmF1bHQ=' | base64 -d ; echo
```

> **🔍 Pentester's Note**
> On Android the call will be `Landroid/util/Base64;->decode(Ljava/lang/String;I)[B` instead of the
> JDK's `java.util.Base64`, and the second `int` argument is the flags word. `0` means `DEFAULT`, `8`
> means `NO_WRAP`, `11` is the common `URL_SAFE | NO_PADDING | NO_WRAP` combination. Note the flag
> value before you decode, because URL-safe alphabets substitute `-` and `_` for `+` and `/`, and a
> naive `base64 -d` will fail or produce garbage.

### Step 5 — Recover the method name

Read `methodName()`.

```bash
# host
sed -n '/method private static methodName/,/end method/p' smali_out/VaultChallenge.smali
```

You will find a `new-array` of `char`, a series of `const/16` and `aput-char` instructions filling in
six values, and then a loop that adds `1` to each element. The `const` values in the Smali are the
character codes *before* the transformation.

Collect the six constants in index order, apply the arithmetic the loop performs, and convert to
characters. Do it by hand on paper first, then check with a one-liner:

```bash
# host — substitute the six values you read out of the Smali
python3 -c "print(''.join(chr(c + 1) for c in [116, 109, 107, 110, 98, 106]))"
```

> **🔬 Under the Hood**
> `javac` compiles a small `char[]` initialiser into individual `bipush`/`castore` pairs, which `d8`
> turns into `const/16` and `aput-char`. A larger array would instead be emitted as a
> `fill-array-data` instruction pointing at a `.array-data` payload block at the end of the method.
> Both forms are trivially readable; the payload block form is actually easier, because baksmali
> prints the whole byte sequence in one place. `SecretVault`'s `SEALED` array is emitted the second
> way — go and look at it.

### Step 6 — Read the hidden method

You now know the class and the method. Open it.

```bash
# host
cat smali_out/SecretVault.smali
```

Two things are there: a `.array-data` payload block containing 35 bytes, and a small loop that XORs
each byte with a key derived from the `int` parameter. You know the parameter from step 3, so you can
compute the key and decrypt the payload entirely by hand.

Write the decryption yourself. Do not skip this by running the program.

```bash
# host — fill in the byte list you read out of the .array-data block,
#        and the key you derived from the constant found in step 3
python3 - <<'PY'
sealed = [0xab, 0xa1, 0xac]      # <- replace with all 35 bytes from the .array-data block
key    = 0x00                    # <- replace with (argument & 0xFF)
print(''.join(chr(b ^ key) for b in sealed))
PY
```

If your key is right, the output begins with `FLAG{`.

Cross-check with the decompiler, which should now be readable rather than mysterious:

```bash
# host
jadx -d jadx_out classes.dex
cat jadx_out/sources/SecretVault.java
cat jadx_out/sources/VaultChallenge.java
```

### Step 7 — Confirm dynamically

Static analysis gave you an answer. A good analyst confirms it, because a wrong constant, a
misread instruction, or a second decryption layer you missed all produce a plausible-looking wrong
result.

**Option A, JVM only, no extra tools.** Ask the runtime which classes it loads. If your static
conclusion about the class name is right, it appears here.

```bash
# host
java -Xlog:class+load=info VaultChallenge 2>&1 | grep -i vault
```

You will see `SecretVault` being loaded from the classpath, which is the proof that `forName` resolved
to the name you decoded. Then simply run it:

```bash
# host
java VaultChallenge
```

Expected:

```
vault says: FLAG{....................................}
```

Compare it character for character against the string you derived in step 6. If they differ, your
static work was wrong somewhere and you should find out where before moving on.

**Option B, Frida, which is the technique that generalises to Android.** This hooks the three
reflection entry points and logs every name that passes through them, so it works regardless of how
the names were computed.

```javascript
// Frida REPL / frida -l reflect-trace.js -f com.example.target
// The equivalent JVM-side idea is Option A; on Android this is the standard approach.
Java.perform(function () {
    var Cls = Java.use('java.lang.Class');

    Cls.forName.overload('java.lang.String').implementation = function (name) {
        console.log('[forName] ' + name);
        return this.forName(name);
    };

    Cls.getDeclaredMethod.overload('java.lang.String', '[Ljava.lang.Class;')
        .implementation = function (name, params) {
            console.log('[getDeclaredMethod] ' + this.getName() + '.' + name);
            return this.getDeclaredMethod(name, params);
        };

    var M = Java.use('java.lang.reflect.Method');
    M.invoke.overload('java.lang.Object', '[Ljava.lang.Object;')
        .implementation = function (receiver, args) {
            var out = this.invoke(receiver, args);
            console.log('[invoke] ' + this.toString() + ' -> ' + out);
            return out;
        };
});
```

The key property of this hook set is that it is **transformation-agnostic**. It does not matter
whether the app used Base64, XOR, AES, character arithmetic, or a table lookup to build the name: the
name must be a plain `String` by the time it reaches `Class.forName`, and the return value must be a
real object by the time it leaves `Method.invoke`. Obfuscation can raise your cost, but it cannot
move the boundary at which the runtime demands plaintext.

---

## Hints

<details>
<summary>Hint 1 — where do I even start?</summary>

Start at `Ljava/lang/Class;->forName`. Look at which register supplies its argument. If that register
was loaded by `const-string`, you are done in one step. If it was loaded by `move-result-object` after
an `invoke-static`, then the name is computed by that method, and you read that method next. This
backwards register trace is the single most useful Smali skill in this chapter.
</details>

<details>
<summary>Hint 2 — how do I know the method is static?</summary>

Look at the first argument to `Method.invoke`. Its signature is
`invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;`, where the first parameter is the
receiver. If the register passed there holds `0x0` — set by `const/4 vN, 0x0` — the receiver is
`null`, and a `null` receiver is only legal for a static method.
</details>

<details>
<summary>Hint 3 — the char array values look like nonsense</summary>

They are meant to. Read them out in *index order*, which means following the `aput-char vSrc, vArr,
vIdx` instructions and noting the index register's value each time, not just reading the constants
top to bottom. Then apply whatever the loop does to each element. Here the loop adds one; in the wild
it is often a XOR with a constant or with the index itself.
</details>

<details>
<summary>Hint 4 — I found the 35 bytes but the decryption produces garbage</summary>

Check the key derivation. The Smali will show something like `and-int/lit16 v0, p0, 0xff` or an
`int-to-byte` conversion. The parameter is `0x5eed`, and only its low byte participates. Also check
that you transcribed the `.array-data` block in order and did not skip a line; there are exactly 35
bytes and the plaintext is exactly 35 characters.
</details>

<details>
<summary>Hint 5 — `base64 -d` says invalid input</summary>

On macOS the flag is `-D` rather than `-d`. On Windows use
`python3 -c "import base64;print(base64.b64decode('...').decode())"`. Also make sure you used
`echo -n` so that no trailing newline is fed into the decoder.
</details>

<details>
<summary>Hint 6 — I want to check my answer without spoiling it</summary>

The flag is exactly 35 characters long, matches `^FLAG\{[a-z0-9_]+\}$`, and its SHA-256 is
`fcb116dee045ee336f6f94912d6d8b4f30883d948fefddba9a8afe6668978681`. Verify with:
`python3 -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" 'YOUR_FLAG'`
</details>

---

## Success criteria

You have completed this lab when all of the following are true.

1. You recovered the flag **before** running `VaultChallenge`, using only `baksmali` output and hand
   computation. The flag is 35 characters, matches `^FLAG\{[a-z0-9_]+\}$`, and has SHA-256
   `fcb116dee045ee336f6f94912d6d8b4f30883d948fefddba9a8afe6668978681`.
2. You can name the hidden class and the hidden method, and state the hidden method's full signature
   including its return type and its single parameter type, citing the Smali instruction that proves
   each part.
3. You confirmed the answer dynamically, either with `-Xlog:class+load=info` or with the Frida hook,
   and the dynamic result matches your static result exactly.
4. You can explain in one paragraph why `setAccessible(true)` appearing next to a computed class name
   is a stronger signal than either one alone.
5. You can list two changes an author could make to this challenge that would defeat your static
   approach, and state the dynamic technique that would still work against each.

---

## Solution

<details>
<summary>Click to reveal the full walkthrough and the flag</summary>

### The hidden call

| Question | Answer | Evidence |
|---|---|---|
| Class | `SecretVault` | `U2VjcmV0VmF1bHQ=` Base64-decodes to `SecretVault` |
| Method | `unlock` | Char codes `116,109,107,110,98,106` are `t,m,k,n,b,j`; the loop adds 1, giving `u,n,l,o,c,k` |
| Modifiers | `private static` | `getDeclaredMethod` plus `setAccessible(true)` plus a `null` receiver at `invoke` |
| Parameter | one `int` | `sget-object Ljava/lang/Integer;->TYPE:Ljava/lang/Class;` stored into the `Class[]` |
| Argument | `0x5eed`, 24301 | `const v1, 0x5eed` then `Integer.valueOf` |
| Return type | `String` | The result flows into `String.valueOf` and then `println` |
| Full signature | `private static String unlock(int seed)` | Combination of the above |

### The decryption

The key is the low byte of the argument: `0x5eed & 0xFF` is `0xED`. XOR each of the 35 payload bytes
with `0xED`.

```python
# host
sealed = [0xab,0xa1,0xac,0xaa,0x96,0x9f,0xde,0x8b,0x81,0xde,0x8e,0x99,0xdc,0xdd,
          0x83,0xb2,0xdc,0x9e,0xb2,0x83,0xdd,0x99,0xb2,0xdd,0x8f,0x8b,0x98,0x9e,
          0x8e,0xd9,0x99,0xdc,0xdd,0x83,0x90]
print(''.join(chr(b ^ 0xED) for b in sealed))
```

### The flag

```
FLAG{r3fl3ct10n_1s_n0t_0bfusc4t10n}
```

### Why the combination is the signal, not any single call

Reflection on its own is ordinary. Android developers use `Class.forName` constantly to probe for an
API that exists only on newer versions, and dependency-injection and serialization frameworks use
`getDeclaredField` and `setAccessible` as their normal mode of operation. Any one of these calls in
isolation tells you almost nothing.

What distinguishes hiding from housekeeping is that all four of these hold at once. The name is
*computed* rather than literal, which means the author paid a cost specifically to keep the name out
of the string table. The lookup is `getDeclaredMethod` rather than `getMethod`, and is followed by
`setAccessible(true)`, which together mean the target is deliberately not part of any public surface.
The receiver is `null` and the argument is a hardcoded constant, so nothing about the call depends on
program state, which rules out the "flexible plugin dispatch" explanation. And the entire block is
wrapped in a catch-everything handler that discards the exception, which means the author expected
failure to be possible and chose to make it invisible.

A compatibility shim looks like the opposite in every one of those four dimensions: literal name,
`getMethod`, no `setAccessible`, and a fallback path that does something meaningful on failure.

### Two ways to defeat the static approach, and the dynamic answers

| Author's escalation | Why static analysis stalls | Dynamic technique that still works |
|---|---|---|
| Encrypt the class name with AES, key derived at runtime from a device identifier or fetched from a server | You cannot evaluate the decryption by hand without the key, and the key does not exist in the artefact | Hook `Class.forName` and read the plaintext argument. The runtime must be given the real name |
| Load the payload as a separate DEX with `DexClassLoader` from a file that is downloaded or decrypted at startup | The class is not in `classes.dex` at all, so there is nothing to disassemble | Hook the `DexClassLoader` constructor to capture the path, then pull the dropped DEX off the device and analyse it; or dump loaded classes from memory |
| Emit `invoke-custom` / `MethodHandle` chains instead of `java.lang.reflect` | The `java.lang.reflect` greps miss entirely | Hook `MethodHandles.Lookup` methods, or trace at the ART level |
| Detect Frida and refuse to run the payload | Nothing executes | Defeat the detection first — see [37 — Root Detection](../../37-RootDetection/README.md) and [67 — Bypassing Protections](../../67-BypassingProtections/README.md) |

The invariant behind every row is the same and is worth memorising: **whatever transformation the app
applies, it must be undone before the runtime is called.** `Class.forName` needs a real class name.
`Method.invoke` needs a real `Method`. `Cipher.doFinal` produces real plaintext. There is always a
boundary where the data is in the clear, and instrumentation lives at that boundary. Static
obfuscation moves your cost, never the boundary.

### What you would write in a report

> The application resolves a class and a method by names that are computed at runtime rather than
> declared as literals, then disables the Java access check with `setAccessible(true)` before
> invoking a non-public method. The class name is stored Base64-encoded and the method name is
> assembled by arithmetic on a character array, which prevents both names from appearing in the DEX
> string table and defeats naive string-based static analysis. The concealed logic decodes a 35-byte
> embedded payload with a single-byte XOR whose key is a hardcoded constant. This construction
> provides no cryptographic protection — the payload was recovered by hand from disassembly in under
> an hour with no execution of the application — but it does indicate deliberate intent to obstruct
> analysis, which should be noted and, where the application is not expected to contain
> anti-analysis logic, treated as an indicator warranting deeper review.

### Where to go next with this skill

[`../scripts/find-reflection.sh`](../scripts/find-reflection.sh) runs step 2 across a whole APK and
groups the hits by category, which is how you would start on a real target rather than on a
thirty-line challenge. [`../examples/ReflectionDemo.java`](../examples/ReflectionDemo.java) is the
same material from the developer's side, annotated with exactly what each construct looks like in
JADX and Smali. Then read [40 — Obfuscation](../../40-Obfuscation/README.md) for what commercial
packers do beyond these three tricks, and [69 — Malware Analysis](../../69-MalwareAnalysis/README.md)
for the triage workflow this lab is a miniature of.

</details>
