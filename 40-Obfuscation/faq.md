# 40 — Obfuscation · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. What is obfuscation, in one sentence, and what is it not?**

Obfuscation is any transformation that preserves what a program *does* while making it harder for a
human to work out what that is. It is not encryption, it is not a security boundary, and it is not a
remediation.

The distinction that matters: a security boundary is a place where a component with privilege refuses
to act on behalf of a component without privilege — the kernel refusing a syscall, `system_server`
refusing a Binder transaction, the TEE refusing to release a key. Obfuscation is none of those. It is a
*presentation* of the same instructions.

---

**2. Why can obfuscation never be a security boundary? Give me the one-breath version.**

**The application must run.** To run, its bytecode must reach ART in a form ART understands. To decrypt
its strings, it must hold the key. To verify a signature, it must execute a comparison whose outcome
can be flipped.

Every protection is applied by code the attacker also controls, on hardware the attacker owns, in a
process the attacker can attach a debugger to. There is no asymmetry available: the defender and the
attacker are running the same program on the same silicon, and the only difference is that the attacker
started later.

---

**3. So is obfuscation pointless?**

No, and saying so is as wrong as saying it is security. It buys **time and skill cost**, which are real
currencies:

| Protection | Cost to a competent analyst |
|---|---|
| None | Minutes |
| Renaming only (R8 default) | Hours |
| Renaming + string encryption | Half a day |
| Plus control-flow flattening | One to three days *per interesting method* |
| Commercial packer + native anti-debug | Days for the first analyst; **hours for the second** |
| Hardened native library with virtualisation | Weeks, and still finite |

Most attacks are casual, automated, or bulk. Raising the floor removes that entire population at
modest cost. What obfuscation never does is stop a targeted analyst, and the failure mode to avoid is
not applying it — it is *believing* it.

---

**4. What is "shared fate" and why do developers not know about it?**

A packer or commercial protector is a **product**, deployed identically across thousands of
applications. The first person to defeat it publishes a general method or a tool. From that moment,
every application using that product costs an attacker one command.

So your app's effective protection level is set by the attention the vendor's *most-targeted* customer
attracts, not by your own risk profile. A small fintech buying the same packer as a heavily attacked
gaming company inherits that company's threat surface.

Developers do not know this because vendors do not sell it that way, and because the protection appears
to work — right up until the day it does not, uniformly, for everyone at once. It is the single most
useful thing you can tell a client evaluating a protector.

---

**5. My client says the API key is "obfuscated, so it's fine". What do I write?**

Not an argument — a demonstration. Then this:

> The credential is recoverable by any party in possession of the application binary. Obfuscation
> delays but does not prevent recovery; in this assessment the value was recovered in approximately
> N minutes using standard tooling, as demonstrated below. The credential must be treated as public
> and the design changed accordingly.

The recovery *time* is what converts an abstract disagreement into a number a risk owner can act on,
and the demonstration is what ends the argument. An assertion invites debate; a recovered key does not.

Note also that the remediation is never "obfuscate it better". It is to stop shipping a credential that
can authorise a privileged operation.

---

**6. What survives obfuscation? I keep being surprised by what is still readable.**

Keep this list; it is the foundation of all manual deobfuscation:

- **Framework class and method names** — `Ljava/lang/String;`, `Landroid/app/Activity;`. They cannot be
  renamed because the platform resolves them by name.
- **Every string constant.** Renaming does not touch the string pool.
- **Manifest component names**, permissions, exported flags, `<queries>`, `<meta-data>`.
- **Resource names** in `resources.arsc`.
- **JNI symbol names** in `.dynsym` — resolved by name at runtime, so renaming would break the link.
- **Reflection target strings** — a `Class.forName("com.x.Y")` argument is a string.
- **Runtime-retained annotations** — Retrofit paths, Gson field names, Room queries.
- **`kotlin.Metadata`**, which frequently carries original names outright.
- **Class hierarchy and method signatures.**
- **Anything with a `-keep` rule.**

That last one is the finding: the classes a developer wrote a keep rule for are exactly the classes
they cared about.

---

**7. Why does the methodology insist on recovering strings before working on control flow?**

Because after renaming, **strings are the only remaining semantics**.

A method called `a` that contains `"/v2/payments/authorize"` is not called `a` any more — it is
`authorizePayment`. You now know that, you can rename it, and every caller becomes partly understood
too. Strings are the seeds from which the naming of the entire program regrows.

Practically, doing them first changes what you have to do next. It frequently makes control-flow work
*unnecessary*, because once you can grep for `/v2/transfer` you land directly in the one method that
matters instead of deflattening forty that do not. **Control flow tells you how; strings tell you
what**, and "what" is what you are being paid to find out.

---

**8. How do I find the string decryptor if I have no idea what cipher it uses?**

You do not need to know. Every string-decryption routine, whatever its algorithm, ends by turning
plaintext bytes into a `java.lang.String`. That is not a property of the cipher; it is a property of the
type system. So hook the constructor and read frame 1 of the stack:

```javascript
// Frida REPL — the universal decryptor finder
Java.perform(function () {
    var S = Java.use("java.lang.String");
    var Ex = Java.use("java.lang.Exception");
    S.$init.overload("[B").implementation = function (b) {
        this.$init(b);
        var st = Ex.$new().getStackTrace();
        if (st.length > 1) console.log("[cand] " + st[1] + " => " + this.toString());
    };
});
```

Run it for ten seconds of app usage, sort the callers by frequency, and the top application-package
entry is your decryptor. This works against XOR, AES, RC4, whitebox implementations and per-class
variants alike, because it hooks the **result**, not the algorithm.

[`scripts/frida-string-decryptor.js`](scripts/frida-string-decryptor.js) is this idea, hardened and
with the exhaustion mode attached.

---

**9. Is AES string encryption meaningfully stronger than XOR?**

No, and the reasoning is worth being precise about.

The threat model of string encryption is "an attacker holds the app". If the attacker holds the app,
they hold the key, because the key must be in the app for the app to work. AES buys exactly one thing:
you cannot recover the strings with a twenty-line Python script that guesses a single byte. You recover
them by **running the decryptor**, which costs the same effort regardless of cipher.

This is a categorically different situation from a real key-management failure — see
[34-Cryptography](../34-Cryptography/README.md). There is no key management here at all; there is a
constant in a file.

---

**10. There are four hundred decryptors, one per class. Does that not defeat the whole approach?**

It defeats the **static** approach completely. Reading one algorithm and reimplementing it in Python is
a twenty-minute job; doing it four hundred times, each with a different key and a slightly different
algorithm, is not a job anyone finishes.

It costs the dynamic approach essentially nothing, because all four hundred converge on the same
`String` constructor. Four hundred decryptors produce four hundred entries in the caller ranking, and
you exhaust them with a loop that never needed to know how many there were.

That asymmetry is the general shape of a good counter-technique: find the place the design *must*
converge, and stand there.

---

**11. What is the difference between passive harvesting and active exhaustion, and why do I need both?**

**Harvest** hooks the decryptor and records what it decrypts as the app runs. It only sees code paths
you actually execute.

**Exhaust** calls the decryptor yourself for every index in its domain. It recovers everything,
including code you never reached.

You need both because the strings you most want live in code you will never trigger by tapping around:
debug endpoints, fallback hosts, error-path credentials, admin paths. Use harvest to *discover* the
decryptor and learn its signature; use exhaust to *census* it.

One caution: exhaustion actually runs app code. A decryptor with side effects can perturb the app, and
four thousand calls in a hundred milliseconds is not a normal execution profile for a monitored app.
Exhaust late in a session, in a process you are happy to discard.

---

**12. My Frida hook installs without error and never fires. What is going on?**

In rough order of likelihood:

1. **You attached instead of spawning.** The code ran during `Application.attachBaseContext` or a
   static initialiser, milliseconds into the process's life. Use `-f … --pause`.
2. **Wrong ClassLoader.** After a packer unpacks, the real classes live in a loader the default class
   factory does not consult. `Java.enumerateClassLoaders`, then set `Java.classFactory.loader`.
3. **Wrong overload.** A class with six methods named `a` will accept a hook on the one that is never
   called. Enumerate `.overloads` rather than guessing.
4. **The method was inlined**, so there is no call for the hook to intercept — see
   [13-ART](../13-ART/README.md) and `cmd package compile -m verify -f`.
5. **The logic is native**, and no Java hook can ever see it.

Note that all five produce the *same* symptom, which is why guessing is expensive and why the first
move is always to establish which one it is.

---

**13. Why must I spawn rather than attach against a packed app? Attaching is more convenient.**

Because everything interesting has already happened. `handleBindApplication` instantiates the packer's
stub, which calls `System.loadLibrary`, which triggers `.init_array`, which runs the anti-debug, and
then `JNI_OnLoad` decrypts the DEX and hands it to a `ClassLoader`. On a modern device that whole
sequence takes single-digit to low-tens of milliseconds.

`frida -U -n` must locate the process, attach, enumerate the Java runtime and install hooks. It is not
a close race.

Note also that `-f` alone is not enough: without `--pause`, Frida resumes immediately and a fast packer
can still beat your script. Pause, confirm your hooks installed, then `%resume`.

---

**14. What is `.init_array` and why does everyone go on about it?**

`.init_array` is an ELF section holding an array of function pointers that the dynamic linker calls
during `dlopen`, after relocations are applied and **before `dlopen` returns**. In C you get an entry
by writing `__attribute__((constructor))`.

Why it matters: a packer's anti-debug lives there, and `JNI_OnLoad` is called *after* `dlopen` returns.
So by the time any hook on `JNI_OnLoad` could fire, the anti-debug has already run — and if it called
`exit(1)`, your process is already gone.

This single detail explains most "my Frida script never fired" confusion against packed apps. To be
earlier you must hook `android_dlopen_ext` (which `System.loadLibrary` ultimately calls) or use spawn
gating, which has you attached before the process's first instruction.

---

**15. How do I know an APK is packed, quickly?**

Any two of these together is conclusive:

- `classes.dex` is tiny relative to the APK — a 40 MB APK with a 90 KB `classes.dex`.
- `class_defs_size` at DEX header offset `0x60` is under about fifty.
- A large, high-entropy file in `assets/` or `res/raw/`.
- `<application android:name>` points at a package that is not the app's.
- A `<meta-data>` element holding a class name (that is where the *real* `Application` name went).
- A `.so` in `assets/` rather than `lib/`, loaded with `System.load(path)`.
- A native library with almost no exports but a populated `.init_array`.

The fastest single command:

```bash
# host
unzip -l app.apk | grep -E 'classes.*\.dex'
```

Two seconds, before any tool is opened. Skipping it is the most expensive minute you can save.

---

**16. Unpacking sounds hard. Is it?**

It is the *least* hard thing in this chapter once you understand the constraint. The packer must hand
ART a complete, valid, **plaintext** DEX, because that is the only thing ART can execute. That
requirement is absolute.

> **Unpacking is not code-breaking. It is timing.** The skill is choosing the moment at which the data
> is in its most complete, least protected state, and being present at that moment with a way to write
> it down.

Three implementations, in order of preference: hook the `ClassLoader` constructors
([`scripts/frida-classloader-dump.js`](scripts/frida-classloader-dump.js)); hook ART's internal DEX
entry points (fragile — those C++ symbols are not a stable ABI, so enumerate at runtime rather than
hard-coding); or scan process memory for the DEX magic
([`scripts/frida-dexdump-lite.js`](scripts/frida-dexdump-lite.js)).

---

**17. I scanned memory for `dex\n` and got two hundred files of garbage. What did I do wrong?**

You searched without validating. A bare four-byte magic search in a live Android process returns
dozens to hundreds of false positives: the literal string inside libart's data, log format strings,
fragments of string pools.

Validate the header:

| Offset | Field | Must be |
|---|---|---|
| `0x04` | version | three ASCII digits then NUL |
| `0x20` | `file_size` | sane, and it must fit inside the mapping |
| `0x24` | `header_size` | **`0x70`** — fixed by the spec for every DEX version ever |
| `0x28` | `endian_tag` | `0x12345678` |

`header_size` and `endian_tag` together are 64 bits of known constant, so random data matches roughly
once in four billion, while a genuine DEX matches always. That is what turns a garbage dump into two or
three files. See [12-DEX-Internals](../12-DEX-Internals/README.md).

---

**18. `jadx` rejects my carved DEX with a checksum error. Is the dump bad?**

Usually not. The in-memory image is legitimately not byte-identical to the file ART originally read —
some fields are patched in place, and regions can be partially rewritten.

The Adler-32 at `0x08` and the SHA-1 at `0x0C..0x1F` are **unkeyed integrity fields**, not
cryptographic signatures. They exist to catch accidental corruption. Recomputing them is legitimate:

```python
# host
import hashlib, struct, zlib, sys
d = bytearray(open(sys.argv[1], "rb").read())
d[0x0C:0x20] = hashlib.sha1(bytes(d[0x20:])).digest()
struct.pack_into("<I", d, 0x08, zlib.adler32(bytes(d[0x0C:])) & 0xFFFFFFFF)
open(sys.argv[1] + ".fixed", "wb").write(bytes(d))
```

If it still fails: `baksmali` is far more tolerant than `jadx`, so go to Smali. If method bodies are
*empty*, you are facing method-level protection — bodies decrypted on first invocation and re-encrypted
afterwards — and the counter is to exercise more of the app and sweep repeatedly.

The APK's real signature, in the APK Signing Block, is a different thing entirely and is a genuine
security control. See [38-TamperDetection](../38-TamperDetection/README.md).

---

**19. What exactly is control-flow flattening, and why do decompilers produce garbage on it?**

Flattening takes a method's basic blocks and lays them side by side as cases of a single `switch`
inside an infinite loop. A state variable holds the number of the block to run next; each block ends by
assigning the next state and jumping back to the top.

Decompilers reconstruct `if`/`while`/`for` by finding **dominance** relationships in the control-flow
graph — block A dominates B if every path to B passes through A, which is what a structured `if` looks
like in graph form. In a flattened CFG the dispatcher dominates everything and nothing dominates
anything else, because every block's only successor is the dispatcher. There is no structure to find.

The decompiler is not failing; it is correctly emitting the only structure that exists. That is why
"wait for a better decompiler" is not a strategy: the information was removed by construction.

---

**20. How do I deflatten something? It looks impossible.**

It looks impossible and takes ten minutes. **Flattening hides order, not information** — every original
block is still there, intact and readable; only the sequence was destroyed, and a sequence is exactly
what a table recovers.

Write one row per case: state, what the block does, next state (which may be conditional). Then sort by
reachability from the entry state, and the original method falls out.

For a method too large to table, hook it and log the state variable at the top of the loop, which
collapses forty cases to the eight that ran.

But ask the right question first: **do you need to understand this method, or only to predict it?** If
you need a value for a given input, hooking the boundary answers that in five minutes and is unaffected
by anything inside. Deflattening is for when you must *reimplement* the logic — forging a token
offline, for example — which is far rarer than the instinct to fully understand every method suggests.

---

**21. The app calls everything through reflection. Is that a serious obstacle?**

To static analysis, yes: cross-references disappear, because `Class.forName("com.x.Y").getMethod("z")`
is not a call edge any tool can follow.

To dynamic analysis, no — it is close to transparent, and in one respect it *helps* you. The reflection
targets are **strings**, and strings survive renaming. An app that reflects on
`javax.crypto.Cipher` has told you it does crypto, in a form you can grep for, in a way a direct call
would also have told you but no more clearly.

Hook `Class.forName`, `Class.getMethod` and `Method.invoke` and you get a live log of every reflective
operation with its target.

---

**22. Should I bother with Smali, or is `jadx` enough?**

`jadx` is enough until it is not, and when it is not, Smali is the answer.

**Smali never fails and never lies.** A decompiler is *reconstructing* Java from bytecode, and
reconstruction can be wrong, incomplete, or refused entirely — which is exactly what anti-decompiler
tricks target. Smali is a direct rendering of the instructions, so there is no reconstruction step to
break.

Go to Smali when: `jadx` errors or produces `// Can't fix method`; you need to patch and rebuild; you
are looking at a flattened method and want the raw `packed-switch` rather than a tidied-up `switch`; or
you want to be certain that what you are reading is what will execute.

---

**23. How do I recognise a commercial protector, and should I name it in my report?**

Recognise it from **observed artefacts**: the shape of the stub, distinctive library names, asset
layout, `<application android:name>`, and the presence of a native runtime. The chapter's
[§3.7.4](README.md#374-commercial-protector-families-descriptively) is a field guide of what is
commonly observed for DexGuard, DexProtector, Jiagu, Bangcle/SecNeo, Tencent Legu, Ijiami, Promon,
Appdome and Arxan/Digital.ai.

Should you name it? Only with a positive, defensible identification. Products change, vendors rename
libraries and ship different tiers to different customers, and a misattributed vendor name in a client
report is worse than no attribution.

What you are actually trying to establish is three things, and the vendor name only matters because it
makes the third one searchable:

1. Is the real code in the APK, or delivered at runtime?
2. Is there a native runtime that will fight my instrumentation?
3. Has anyone published a general method for this shape?

---

**24. `apktool` fails but the app installs and runs. Is the APK corrupt?**

No — it demonstrably runs, so it is valid by the only definition that matters. You have found
deliberate format abuse.

The underlying asymmetry: `PackageManager`, `dexopt` and ART were written for speed and backwards
compatibility and accept a wider range of inputs than `apktool`, `jadx`, `baksmali` and `dex2jar`,
which were written to a stricter reading of the specification. That gap is exploitable, and exploiting
it is effective because most analysts stop when the tool errors.

What to do: try `jadx -J-Xmx8g --show-bad-code --deobf`; drop to `baksmali`, which is more tolerant;
work on a case-sensitive filesystem (illegal identifier names cause file collisions); or skip static
analysis and dump from memory. And note it in the report — an app that deliberately breaks analysis
tooling is making a statement about its threat model.

---

**25. Does moving code into a native library actually help the developer?**

It raises cost and changes nothing fundamental. Three plaintext choke points remain:

- **The JNI boundary.** Every value crossing between Java and native is observable, and
  `frida-trace -i 'Java_*'` gives you the whole conversation for free. Do this *before* opening Ghidra.
- **libc.** File access, networking and process control go through symbols you can interpose on.
- **The crypto libraries.** `libcrypto`/`libssl` and the platform providers are hookable.

`RegisterNatives` removes the `Java_*` symbol anchor, which is worth doing because it costs the
developer nothing — but it costs an attacker minutes, not hours: hook `RegisterNatives` itself, or read
the `JNINativeMethod` array out of `JNI_OnLoad` in Ghidra, where the names and signatures sit as plain
strings.

Native migration is a legitimate cost-imposition measure. It is not a category change.

---

**26. What is the single fastest thing I can do on a new obfuscated target?**

```bash
# host
scripts/apk-obfuscation-triage.sh target.apk
```

Twenty minutes of triage saves days, and the six-row table it produces determines everything downstream
*and* is the first table in your report. A client asking "is our app protected?" is asking for exactly
those six rows.

If you want one command rather than a script: `unzip -l target.apk | grep classes` — because if it is
packed, nothing else you were about to do was going to work.

---

**27. Is MobSF or any automated tool enough?**

No, and the reason generalises: **automated tools report capability; only manual confirmation reports
behaviour.**

An automated scan will tell you a string exists, a permission is declared, an API is referenced. It
cannot tell you whether the code path runs, whether the string is used, or whether the finding matters.
It produces false positives (a path string in an unused library, an SDK that never initialises) and
false negatives (anything in native code, anything behind encrypted strings, anything reached
reflectively).

Use it for lead generation and coverage. Verify every hit dynamically before it enters a report,
because an unverified automated finding in a deliverable is how you lose a client's trust in everything
else you wrote.

---

**28. As a developer, what should I actually do?**

In this order, and stop when the budget runs out:

1. **Enforce security decisions on the server.** If a modified client can call your endpoint and it
   works, nothing below this line matters.
2. **Ship no secret that can authorise a privileged operation.** No amount of obfuscation fixes a
   client-side credential; only removing it does.
3. **Turn on R8 with tight keep rules.** It is free, it shrinks the app, and over-broad keep rules are
   the single most common way the obfuscation a company pays for fails to cover the code it cares
   about. Audit them.
4. **Encrypt strings** if you want to slow bulk automated analysis. Understand that it costs an analyst
   half a day at most.
5. **Consider a packer** only with shared fate understood, and price the ongoing costs honestly:
   unreadable crash reports, broken profiling, device compatibility issues, and a hard vendor
   dependency.
6. **Do not ship the mapping file.** It is total disclosure, and it happens more often than you would
   believe — check your own APK for `mapping.txt`.

---

**29. Why does my `-keep` rule list keep growing, and why is that a security problem?**

Because reflection, serialisation libraries, JNI and dependency injection all resolve things by name at
runtime, so anything they touch must survive renaming, and the easiest fix for a crash is a broader
rule. `-keep class com.example.** { *; }` makes the crash go away and makes the obfuscation
meaningless for that package.

It is a security problem for two reasons. First, coverage: the classes you kept are frequently the
crypto, auth and payment classes, because those are the ones with reflective or serialised interfaces.
Second, disclosure: your keep rules are a list, in your own build, of what you considered important —
and after R8 the classes that still have real names are exactly those, which is a signposted route
through your app for anyone reading it.

Audit keep rules as a security control. "Which of our classes still have their original names, and
why?" is a question worth asking every release.

---

**30. What does a good obfuscation finding look like in a report?**

Not "the app is obfuscated" and not "the obfuscation was bypassed". Both are statements about your
process rather than about risk.

A good finding names the **coverage gap**, quantifies the **recovery effort**, and states what the
recovered material **lets an attacker do**:

> Obfuscation coverage is inconsistent with the stated threat model. Identifier renaming is applied
> across the application, but keep rules exempt `com.client.crypto.**` and `com.client.payments.**`,
> which retain original class, method and field names. String encryption is not applied. As a result
> the payment signing key derivation was reconstructed in approximately forty minutes, and the derived
> key permitted forging a valid `X-Signature` header for arbitrary transfer requests, which the server
> accepted (see finding 3). The obfuscation applied delays casual analysis of the user-interface layer
> and provides no protection to the components it was presumably intended to protect.

Note the shape: a measured number, a named gap, and an impact that is not about obfuscation at all.
That last part is usually where the real finding was.
