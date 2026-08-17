# Lab 02 — Strings, `==`, and the DEX string table

> Part of [04 — Java](../README.md). Difficulty: beginner to intermediate.
> Prerequisite lab: [Lab 01 — Hello World to DEX](lab-01-hello-to-dex.md).

---

## Objective

Build a small login check that contains two of the most common real-world Java defects at once — a
password compared with `==` instead of `.equals()`, and that password hardcoded as a literal — then
demonstrate both from the attacker's side and fix both properly.

By the end you will be able to do three things unaided. You will be able to explain why the broken
comparison sometimes returns `true` and sometimes returns `false` for the same characters, which is
what makes this bug survive testing. You will be able to pull the hardcoded credential out of a DEX
file without running the application. And you will be able to recognise the defect in Smali by the
*absence* of a specific instruction, which is a skill that transfers to almost every comparison bug
you will ever review.

---

## Prerequisites

- Everything from [Lab 01](lab-01-hello-to-dex.md): a JDK 17+, `d8`, `jadx`, `baksmali`.
- Python 3.8 or newer, for [`../scripts/dump-strings.py`](../scripts/dump-strings.py). No packages to
  install; the script is standard library only.
- On Linux or macOS, the `strings` utility, which is part of binutils. Windows users should skip the
  `strings` step and use the Python script, because the Sysinternals `strings.exe` is a different
  tool with different flags.

> **📖 Definition**
> **String pool** (also called the string intern pool) — a table the runtime maintains of unique
> `String` objects. Every string *literal* that appears in compiled code is automatically placed in
> this pool, and every occurrence of the same literal text anywhere in the program resolves to the
> single pooled object. Strings built at runtime, read from input, or created with `new String(...)`
> are **not** in the pool unless you call `.intern()` on them.

**Estimated time:** 45 to 75 minutes.

---

## Setup

```bash
# host
mkdir -p ~/lab02-login && cd ~/lab02-login
```

Create `Login.java` with exactly this content.

```java
// host — save as ~/lab02-login/Login.java
public class Login {

    private static final String SECRET = "hunter2-s3cr3t";

    private boolean checkBroken(String supplied) {
        return supplied == SECRET;          // the defect
    }

    private boolean checkFixed(String supplied) {
        return SECRET.equals(supplied);     // the naive fix
    }

    public static void main(String[] args) {
        Login login = new Login();

        String fromLiteral = "hunter2-s3cr3t";
        String fromInput   = args.length > 0 ? args[0] : new String("hunter2-s3cr3t");
        String fromBuilder = new StringBuilder("hunter2").append("-s3cr3t").toString();

        System.out.println("literal  broken=" + login.checkBroken(fromLiteral)
                         + " fixed=" + login.checkFixed(fromLiteral));
        System.out.println("input    broken=" + login.checkBroken(fromInput)
                         + " fixed=" + login.checkFixed(fromInput));
        System.out.println("builder  broken=" + login.checkBroken(fromBuilder)
                         + " fixed=" + login.checkFixed(fromBuilder));
        System.out.println("interned broken=" + login.checkBroken(fromBuilder.intern())
                         + " fixed=" + login.checkFixed(fromBuilder.intern()));
    }
}
```

Four different ways of producing the identical fourteen characters `hunter2-s3cr3t`. That is the
whole point of the lab.

---

## Steps

### Step 1 — Observe the bug

```bash
# host
javac -g Login.java
java Login
java Login hunter2-s3cr3t
```

Expected output, identical for both runs:

```
literal  broken=true fixed=true
input    broken=false fixed=true
builder  broken=false fixed=true
interned broken=true fixed=true
```

Stop and read that table before continuing, because it explains why this bug reaches production.

The `literal` row passes the broken check. A developer writing a unit test almost always writes
`assertTrue(login.checkBroken("hunter2-s3cr3t"))` with a literal, because that is the natural way to
write a test. That literal resolves to the same pooled object as `SECRET`, so `==` compares a
reference against itself and returns `true`. **The unit test passes.** The bug is invisible.

The `input` row fails. A string that came from `args`, from a text field, from a network response, or
from a file is a freshly allocated object. It is never in the pool. So `==` compares two different
objects and returns `false`, and the real user with the correct password is rejected.

The `builder` row fails for the same reason: `StringBuilder.toString()` allocates.

The `interned` row passes, which is the detail that makes this bug genuinely confusing to debug.
Calling `.intern()` looks up the pool and returns the pooled instance, so identity comparison
suddenly works again. If any library in the call path interns strings, the behaviour flips.

> **⚠️ Warning**
> The direction of the failure here is "correct password rejected", which is a usability bug rather
> than a security bug. Reverse the condition and it becomes a security bug. Code of the form
> `if (suppliedToken != expectedToken) { denyAccess(); }` fails **open** when both references happen
> to be the same pooled object, and code of the form
> `if (role == "admin") { grant(); }` grants access to anyone whose role string happens to be a
> literal from the same compilation unit. Always work out which way a comparison bug fails before
> deciding its severity.

### Step 2 — See the defect in bytecode

```bash
# host
javap -c -p Login.class
```

The two methods are only a few instructions each, and the difference is stark:

```
  private boolean checkBroken(java.lang.String);
    Code:
       0: aload_1
       1: ldc           #9                  // String hunter2-s3cr3t
       3: if_acmpne     10
       6: iconst_1
       7: goto          11
      10: iconst_0
      11: ireturn

  private boolean checkFixed(java.lang.String);
    Code:
       0: ldc           #9                  // String hunter2-s3cr3t
       2: aload_1
       3: invokevirtual #11                 // Method java/lang/String.equals:(Ljava/lang/Object;)Z
       6: ireturn
```

The broken version uses `if_acmpne`, where the `a` means "reference" and `cmp` means "compare". It is
a pointer comparison, executed in a single machine instruction after JIT compilation. The fixed
version calls `String.equals`, which compares lengths and then contents.

Note also that both methods contain `ldc #9`, the *same* constant pool entry. The compile-time
constant inlining you measured in Lab 01 is happening here too: neither method reads the `SECRET`
field.

> **🔍 Pentester's Note**
> This is your review heuristic, and it is more reliable than reading decompiled source. When you
> find a comparison involving anything credential-shaped — a password, a token, a PIN, an HMAC, a
> signature, a licence key — look for a call to `equals`, `equalsIgnoreCase`, `compareTo`,
> `Arrays.equals`, or `MessageDigest.isEqual`. If there is no call instruction at all and you see a
> bare reference comparison, you have found a bug. The absence of an instruction is the finding.

### Step 3 — Convert to DEX and find the same shape in Smali

```bash
# host
d8 --min-api 21 Login.class --output .
baksmali d classes.dex -o smali_out
sed -n '/checkBroken/,/end method/p' smali_out/Login.smali
sed -n '/checkFixed/,/end method/p'  smali_out/Login.smali
```

The broken method appears in a form close to this. Exact registers and label numbers vary by `d8`
version.

```smali
# baksmali output — representative
.method private checkBroken(Ljava/lang/String;)Z
    .registers 3

    const-string v0, "hunter2-s3cr3t"

    if-ne p1, v0, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    return v1
.end method
```

```smali
# baksmali output — representative
.method private checkFixed(Ljava/lang/String;)Z
    .registers 3

    const-string v0, "hunter2-s3cr3t"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    return v0
.end method
```

In DEX there is no separate reference-comparison opcode. `if-ne` and `if-eq` operate on registers
regardless of whether those registers hold an `int` or an object reference; the verifier keeps track
of which. So the fingerprint in Smali is precisely the same as in JVM bytecode: a comparison of two
registers that hold `Ljava/lang/String;` values, with no `invoke-virtual` to `equals` anywhere near
it.

Turn that into a grep you can run against a real application.

```bash
# host — find every string literal that feeds a bare register comparison
grep -n -A 3 'const-string' smali_out/Login.smali | grep -B 1 -E 'if-(eq|ne) '
```

### Step 4 — Recover the credential from the DEX without running anything

This is the part that matters most in a real engagement, because you usually receive an APK and no
source. There are three ways to do it, in increasing order of precision.

**The crude way** — scan the file for printable byte runs.

```bash
# host — Linux and macOS only
strings -a -n 8 classes.dex | grep -i hunter
```

```
hunter2-s3cr3t
```

This works but produces enormous noise on a real APK, because it will happily report fragments of
type descriptors, method names, and compressed data that happen to look printable.

**The precise way** — parse the DEX string table directly.

```bash
# host
python3 ../04-Java/scripts/dump-strings.py classes.dex --min-len 6
```

Adjust the path to wherever you cloned the repository. The script reads the DEX header, seeks to
`string_ids_off`, walks `string_ids_size` four-byte offsets, and decodes each `string_data_item`. It
therefore reports exactly the strings the application declared, in table order, with no false
positives from binary noise.

Run the heuristic mode to see what an automated first pass flags:

```bash
# host
python3 ../04-Java/scripts/dump-strings.py classes.dex --min-len 6 --heuristic
```

**The contextual way** — find where the string is used, not just that it exists.

```bash
# host
grep -rn 'hunter2-s3cr3t' smali_out/
```

Knowing that the string exists tells you there is a secret. Knowing which method contains the
`const-string` tells you what the secret is *for*, which is the difference between a low-severity
"hardcoded string" note and a real finding.

> **🔬 Under the Hood**
> A DEX file has a single `string_ids` table shared by the entire application. Class names, method
> names, field names, type descriptors, and every string literal all live in it. The table is sorted
> by the string's UTF-16 code point order, which is why `dump-strings.py` output comes out in a
> strange but consistent order and why binary search on it is cheap for the runtime. The full format
> is covered in [12 — DEX Internals](../../12-DEX-Internals/README.md).

### Step 5 — Confirm with the decompiler

```bash
# host
jadx -d jadx_out classes.dex
cat jadx_out/sources/Login.java
```

JADX will render `checkBroken` as `return supplied == "hunter2-s3cr3t";` or a close variant. Note
that JADX shows the *inlined literal*, not the field name, for the same compile-time constant reason
you measured in Lab 01.

At this point you have found the credential three independent ways. In a report, cite the Smali
`const-string` with its file and line, because that is the evidence that survives an argument about
decompiler accuracy.

### Step 6 — Fix it properly

Now write the remediation. There are two separate defects, and fixing only one is a common mistake.

**Defect A, the comparison.** Replace `==` with a value comparison. But `equals` is still not the
right answer for a credential, because `String.equals` returns as soon as it finds a differing
character, which leaks information about how many leading characters were correct through timing.
For anything secret, compare in constant time.

**Defect B, the hardcoded secret.** No amount of comparison fixing helps when the expected value is
sitting in the string table. The secret must not be in the app at all. The correct architecture is
that the client sends the credential to a server which verifies it, or — if a local check is genuinely
required, for example an offline PIN — the app stores only a salted, slow hash of the value and never
the value itself.

Create `LoginFixed.java`:

```java
// host — save as ~/lab02-login/LoginFixed.java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class LoginFixed {

    // Defect B fixed: no plaintext secret. These two values are what a server or
    // an enrolment step would have produced and stored. Neither reveals the password.
    private final byte[] salt;
    private final byte[] expectedHash;

    private LoginFixed(byte[] salt, byte[] expectedHash) {
        this.salt = salt.clone();
        this.expectedHash = expectedHash.clone();
    }

    static LoginFixed enrol(char[] password) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return new LoginFixed(salt, derive(password, salt));
    }

    private static byte[] derive(char[] password, byte[] salt) throws Exception {
        // PBKDF2 is deliberately slow, so a stolen hash is expensive to brute force.
        PBEKeySpec spec = new PBEKeySpec(password, salt, 120_000, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                                   .generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();   // wipe the copy PBEKeySpec made
        }
    }

    // Defect A fixed: value comparison, in constant time.
    boolean check(char[] supplied) throws Exception {
        byte[] candidate = derive(supplied, salt);
        try {
            return MessageDigest.isEqual(candidate, expectedHash);
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }

    public static void main(String[] args) throws Exception {
        char[] real  = "hunter2-s3cr3t".toCharArray();
        LoginFixed guard = enrol(real);
        Arrays.fill(real, '\0');            // the password can be wiped: it is a char[]

        char[] good = "hunter2-s3cr3t".toCharArray();
        char[] bad  = "hunter2-s3cr3u".toCharArray();

        System.out.println("correct password accepted: " + guard.check(good));
        System.out.println("wrong   password accepted: " + guard.check(bad));

        Arrays.fill(good, '\0');
        Arrays.fill(bad,  '\0');
    }
}
```

```bash
# host
javac LoginFixed.java
java LoginFixed
```

Expected output:

```
correct password accepted: true
wrong   password accepted: false
```

### Step 7 — Prove the fix removed the string from the artefact

```bash
# host
d8 --min-api 21 LoginFixed.class --output fixed_out/
python3 ../04-Java/scripts/dump-strings.py fixed_out/classes.dex --min-len 6 | grep -i hunter
```

The demonstration `main` method still contains the literal, because it has to construct a test
password from somewhere. Delete `main`, or move it to a separate test class, recompile, and re-run
the string dump. Now nothing matches. That is the deliverable: the shipped artefact contains a
PBKDF2 call and no credential.

> **🧠 Mental Model**
> Ask of every secret: "if I hand this APK to a stranger, what do they learn?" A hardcoded string
> teaches them the secret. A salted PBKDF2 hash teaches them only that a password exists and costs
> them 120 000 iterations per guess. The comparison operator is a correctness question; where the
> expected value lives is the security question. Fix both, in that order of importance: the second
> one first.

---

## Hints

<details>
<summary>Hint 1 — all four rows print `true` on my machine</summary>

You almost certainly passed the password as a command-line argument on a JVM that interned it, or
your JVM applied an optimisation. Re-run with no arguments so the `new String(...)` branch is taken.
If the `builder` row still prints `broken=true`, print the identity hash codes to check:
`System.out.println(System.identityHashCode(fromBuilder) + " " + System.identityHashCode(fromLiteral));`
They must differ.
</details>

<details>
<summary>Hint 2 — `dump-strings.py` says the magic is wrong</summary>

You pointed it at `Login.class` rather than `classes.dex`, or at an APK whose DEX is stored under a
different name. The script accepts either a raw `.dex` file or an `.apk`; for an APK it enumerates
every `classes*.dex` entry. Check the first eight bytes yourself with
`od -A d -t x1 -N 8 classes.dex`; you want `64 65 78 0a 30 33 35 00`.
</details>

<details>
<summary>Hint 3 — I cannot find the string in the Smali</summary>

Search case-insensitively and search all `smali*` directories, because a large app is split across
`smali`, `smali_classes2`, `smali_classes3` and so on:
`grep -rni 'hunter' smali*/`. If the app uses string encryption, the literal will not be there at all
in plaintext; that case is the subject of [Lab 03](lab-03-reflection-hunt.md).
</details>

<details>
<summary>Hint 4 — why is `MessageDigest.isEqual` the right comparison?</summary>

Because it is documented to compare all bytes regardless of where the first difference occurs, so its
running time does not depend on how many leading bytes matched. `Arrays.equals` and `String.equals`
both return early. On a local, offline check the timing channel is usually not practically
exploitable, but using the constant-time primitive costs nothing and removes the argument entirely.
</details>

<details>
<summary>Hint 5 — my fixed version is slow</summary>

That is the point. PBKDF2 with 120 000 iterations is deliberately expensive. Tune the iteration count
so that a single check takes roughly 100 milliseconds on your target's slowest supported device, and
never lower it below the current OWASP guidance. On Android, prefer delegating this to the hardware
keystore where possible — see [49 — KeyStore](../../49-KeyStore/README.md).
</details>

---

## Success criteria

You have completed this lab when all of the following are true.

1. You can state, for each of the four rows in the step 1 output, why the broken check returned what
   it returned, using the words "pooled" and "allocated" correctly.
2. You can point to `if_acmpne` in the `javap` output and to the corresponding `if-ne` in the Smali,
   and explain that the finding is the missing `invoke-virtual` to `String.equals`, not the presence
   of any particular instruction.
3. You have recovered the literal `hunter2-s3cr3t` from `classes.dex` by at least two independent
   methods, one of which is [`dump-strings.py`](../scripts/dump-strings.py), and you can name the
   Smali file and line number where it is used.
4. `LoginFixed` compiles, accepts the correct password, rejects the wrong one, and — with the
   demonstration `main` removed — produces a DEX in which no string dump reveals the credential.
5. You can write, in three sentences, the developer-facing remediation you would put in a report: what
   is wrong, why it is wrong, and the exact code change.

---

## Solution

<details>
<summary>Click to reveal the full explanation</summary>

### Why each row behaves as it does

| Row | Source of the string | In the pool? | `==` result | Reason |
|---|---|---|---|---|
| `literal` | a `String` literal in `main` | yes | `true` | Both operands resolve to the single pooled instance for that character sequence |
| `input` | `args[0]` or `new String(...)` | no | `false` | The runtime allocated a fresh object; the characters match but the references do not |
| `builder` | `StringBuilder.toString()` | no | `false` | `toString()` constructs a new `String` every call |
| `interned` | `.intern()` on the builder result | yes | `true` | `intern()` looks the value up in the pool and returns the pooled instance |

The characters are identical in all four rows. Only object identity differs, and `==` only ever asked
about identity.

### Why this bug survives to production

Because the natural unit test uses a literal, and literals are pooled. Every test passes. The bug only
appears when a value arrives from outside the compilation unit, which is exactly the path a test
usually does not exercise. This is a general lesson about reference-equality bugs: they are
*correlated with test data*, not with code paths, so coverage metrics do not find them.

### Severity analysis

The direction matters more than the presence of the bug.

| Code shape | Fails when | Consequence |
|---|---|---|
| `if (supplied == SECRET) grant();` | supplied is not pooled | Fails closed. Denial of service, correct users rejected |
| `if (supplied != SECRET) deny();` | supplied is pooled | Fails open. Anyone supplying a literal-sourced value from the same DEX is granted access |
| `if (role == "admin") grant();` | role came from a literal anywhere in the app | Fails open. Privilege escalation |
| `if (token == null \|\| token == expected)` | mixed | Both, depending on the branch |

Report a fail-open reference comparison on a security decision as high severity. Report a fail-closed
one as a correctness defect with a note that a single edit flips it to high.

### Where the secret actually lives in the artefact

The string `hunter2-s3cr3t` is a `string_data_item` in the DEX `string_ids` table. It is referenced by
a `const-string` instruction with an index into that table. Both `checkBroken` and `checkFixed`
contain that instruction, because the compile-time constant was inlined into both. The `SECRET`
static field still exists in the class definition with a `static_values` entry, so a third way to
recover the value is to read the field's encoded initial value directly from the class definition
rather than from any instruction.

Recovery methods and what each is good for:

| Method | Command | Strength | Weakness |
|---|---|---|---|
| Byte scan | `strings -a -n 8 classes.dex` | Works on any binary, needs no parser | Enormous noise, misses non-ASCII, no context |
| String table parse | `dump-strings.py classes.dex` | Exactly the declared strings, no false positives | Tells you the string exists but not where it is used |
| Smali grep | `grep -rn 'hunter' smali_out/` | Gives you file, line, and enclosing method | Requires a full disassembly pass |
| Decompiler | `jadx` then read | Most readable | Can be defeated or confused by obfuscation |

Use the string table to decide whether it is worth disassembling, then use Smali for evidence.

### The remediation paragraph you would write in a report

> The application compares the user-supplied password against the expected value using reference
> equality (`==`) rather than value equality, in `Login.checkBroken`. Reference equality compares
> object identity, so the comparison succeeds only when both operands happen to be the same interned
> object; a password arriving from user input is never interned, so the check does not test what the
> developer intended. Separately and more seriously, the expected password is embedded in the
> application as a string literal and is recoverable from `classes.dex` with a single command, so the
> check provides no security regardless of the operator used. Replace the local check with
> server-side verification. Where an offline check is unavoidable, store only a salted PBKDF2, scrypt,
> or Argon2 hash of the credential, and compare derived values with `MessageDigest.isEqual` so that
> the comparison is constant time. Hold credentials in `char[]` rather than `String` so that they can
> be zeroed after use.

### Mapping to the standards

| Standard | Control | How this lab maps |
|---|---|---|
| MASVS | `MASVS-STORAGE-1` | The credential is stored insecurely, as a plaintext literal in the DEX |
| MASVS | `MASVS-CRYPTO-1` | The comparison is neither a value comparison nor constant time |
| MASVS | `MASVS-AUTH` family | An authentication decision is made client-side against a client-held secret |
| MASTG | Search the test index for hardcoded secrets and for object persistence | See [`../references/README.md`](../references/README.md) |

### One more thing to notice

`checkBroken` and `checkFixed` are both `private`. That did not stop you reading either of them, and
it did not stop you extracting the secret. Hold on to that observation; it is the entire premise of
[Lab 03](lab-03-reflection-hunt.md), where an application tries much harder to hide something and
still fails.

</details>

---

## Next

Continue to [Lab 03 — Reflection hunt](lab-03-reflection-hunt.md).
