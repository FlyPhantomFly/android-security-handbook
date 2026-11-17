# Lab 03 — Recovering dynamically registered natives

**Difficulty:** Advanced
**Time:** 3–5 hours
**Prerequisites:** [Lab 01](lab-01-building-the-bridge.md) · [Lab 02](lab-02-references-and-exceptions.md) ·
[Chapter 16 §3.8](../README.md#38-dynamic-registration--registernatives) ·
[§6.5](../README.md#65-recognising-a-jninativemethod-table-by-eye) ·
[§7.2](../README.md#72-dumping-the-dynamic-registration-table) ·
[57 Ghidra](../../57-Ghidra/README.md)

**What you need:**

| Requirement | Needed for | If you do not have it |
|---|---|---|
| Frida + a rooted device or emulator | Parts 3–5 | frida-gadget in a repackaged debuggable build works too |
| Ghidra (or IDA / radare2) | Part 6 | Part 6 is optional; Parts 1–5 stand alone |
| Android NDK | Part 2 (building the target) | Use any real app that registers dynamically instead |
| `nm`, `readelf`, `strings` | Parts 1–2 | NDK `llvm-*` equivalents |

---

## Objective

Static analysis cannot see a dynamically registered native method. This lab is about the fact that
**runtime analysis always can**, and about why that asymmetry is structural rather than accidental.

By the end you will be able to:

1. Recognise, from an APK alone, that an app is registering dynamically — and say which library.
2. Recover the complete name → signature → address mapping at runtime.
3. Rebase a recovered address into a disassembler and land on the right function.
4. Recover the same table *statically* from `JNI_OnLoad`, and explain when that method fails.
5. Explain, precisely, why obfuscation cannot prevent the runtime recovery.

---

## Background, in one paragraph

A `native` method can be bound two ways. Static registration matches an exported symbol whose name is
mangled from the class and method — visible to `nm -D`, and it forces the class name to survive
obfuscation. Dynamic registration calls `RegisterNatives(env, clazz, table, count)` with a table of
`{name, signature, fnPtr}`, usually from `JNI_OnLoad`. The implementation functions can then be
`static` (internal linkage, no symbol at all), and the Java class is free to be renamed to `a.b.c`.
This is exactly why commercial protectors use it. And it is exactly why hooking `RegisterNatives`
works: **ART must be handed the name and signature in plaintext**, because it looks the method up on
the class by exact string comparison. The registration call is a mandatory chokepoint.

---

## Part 1 — Spot it from the APK

Use the target you triaged in Lab 01 Part 3, or a new one.

### 1.1 The negative result

```bash
# host
for so in work/lib/arm64-v8a/*.so; do
  n=$(nm -D --defined-only "$so" 2>/dev/null | grep -c ' Java_')
  o=$(nm -D "$so" 2>/dev/null | grep -c 'JNI_OnLoad')
  printf '%-40s Java_*=%-4s JNI_OnLoad=%s\n' "$(basename "$so")" "$n" "$o"
done
```

The signal you are looking for is a row with `Java_*=0` and `JNI_OnLoad=1`.

### 1.2 Confirm from the Java side

```bash
# host
apktool d -f -o out target.apk >/dev/null
grep -rn "^\.method.*\bnative\b" out/smali*/ | wc -l
```

If the DEX declares native methods and no library exports a matching symbol, the binding must be
dynamic. That is the diff, and `jni-triage.sh` computes it for you:

```bash
# host
bash ../scripts/jni-triage.sh target.apk
```

Read report 5. Every method it lists is your work for the rest of this lab.

### 1.3 What still leaks

```bash
# host
strings -a work/lib/arm64-v8a/libtarget.so | grep -E '^\([A-Z\[L]' | sort -u
```

`RegisterNatives` needs the signature as a plain string, so unless the author encrypted it, the
descriptors are right there. You now know the *shape* of every registered method — how many
parameters and of what types — before you know a single name or address.

Write down what you learn from the signatures alone. For example, `([BLjava/lang/String;)[B` on a
library named `libattest.so` is telling you something even with no name attached.

---

## Part 2 — Build a known target

Reverse-engineering something whose answer you already know is the fastest way to learn the
technique. Build `../examples/dynamic_registration.c` — the one-command route is
[`../examples/build.sh`](../examples/build.sh) — together with the `Guard` class the file's header
specifies.

Now verify the properties the example claims, and **do not skip the ones that fail**. Two of the
four did, when this lab was finally run against a real compiler, and the failures are worth more
than the successes. The output below is measured, from NDK 25.2.9519653, `arm64-v8a`, `-O2`:

```bash
# host — 1. the implementations have no exported names. TRUE.
llvm-nm -D --defined-only libguard.so | grep ' T '
#   000000000000183c T JNI_OnLoad
#   0000000000001aac T JNI_OnUnload
#   ... and nothing else

# host — 2. the signatures are gone. FALSE.
llvm-strings -a libguard.so | grep -E '^\([A-Z\[L]'
#   (Z)V
#   (L%s/%s/String;)Z

# host — 3. the class name is XORed away. FALSE at -O2.
llvm-strings -a libguard.so | grep -i 'com/example'
#   com/example/jnidemo/Guar([B)[B
```

Take those two failures one at a time, because each teaches a different thing.

**The signatures.** `(Z)V` is the `onVerdict` callback descriptor, passed as a plain literal to
`GetMethodID`, so it is in `.rodata`. `(L%s/%s/String;)Z` is the *template* the file
assembles with `snprintf` at runtime — the finished `(Ljava/lang/String;)Z` never exists in the
file. So the honest statement is not "the signatures are assembled at runtime and therefore absent";
it is **"a signature is absent only if every one of its call sites assembles it"**, and one
un-assembled `GetMethodID` puts it back. That is a realistic failure mode: obfuscation applied to
the registration table but not to the callback lookup is a pattern you will meet in shipped apps.

**The class name.** This is the more interesting one, and it is covered in full in
[`../examples/README.md`](../examples/README.md#the--o2-result-a-claim-on-this-page-was-wrong).
Short version: clang constant-folds the XOR loop at `-O2` and writes 24 of the 25 plaintext
characters into `.rodata`, leaving the 25th (`'d'`) as an immediate operand. Rebuild the same file at
`-O0`, `-O1`, `-Os` and `-Oz` and the string genuinely disappears at all four. Run
`../examples/build.sh` and read step 3 of its output; it prints that table for you.

> **Pentester's Note**
> A plaintext identifier that is exactly **one character short** — `com/example/jnidemo/Guar`,
> `getRuntim`, `/system/xbin/s` — is a fingerprint, not a coincidence. It means a de-obfuscation
> routine was constant-folded and the tail byte became an immediate. Find the cross-reference to
> that string and look for a nearby `mov` of a printable ASCII value; it completes the name. Do not
> record the truncated form in a report.

So what *has* the obfuscation actually cost the analyst? Less than the example's author believed:
the three method **names** (`check`, `seal`, `nativeInit`) are still absent, because those are built
by `snprintf("%s%s", "ch", "eck")` and friends — and you can see the fragments `ch`, `eck`, `se`,
`al`, `native`, `Init` in `.rodata` without knowing which pairs with which. That is the residue
worth attacking, and Part 3 recovers it in one command.

The three methods registered are `check(Ljava/lang/String;)Z`, `seal([B)[B` and `nativeInit()J`. You
know that because you have the source. An analyst does not — and, as the two failures above show,
neither does the author of an obfuscation scheme who never looked at the binary.

---

## Part 3 — Recover it at runtime

### 3.1 Spawn, do not attach

```bash
# host
frida -U -f com.example.jnidemo -l ../scripts/dump-registernatives.js --no-pause
```

Expected output:

```text
[*] dump-registernatives.js  pointerSize=8  arch=arm64
[+] RegisterNatives hooked via _ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
[dlopen] /data/app/~~.../lib/arm64/libguard.so

[jni] class=com.example.jnidemo.Guard  count=3  table=libguard.so+0x...
      check                    (Ljava/lang/String;)Z                        -> libguard.so+0x...
      seal                     ([B)[B                                       -> libguard.so+0x...
      nativeInit               ()J                                          -> libguard.so+0x...
```

**Everything the obfuscation removed is back.** The class name that was XORed, the method names that
were assembled from fragments, the signatures that were built with `snprintf` — all plaintext,
because ART required them to be.

### 3.2 Prove the spawn requirement

Now attach to the already-running process instead:

```bash
# host
frida -U -n com.example.jnidemo -l ../scripts/dump-registernatives.js
```

Nothing. `JNI_OnLoad` ran during `System.loadLibrary` in a static initialiser, long before you could
attach.

**Write this down as a rule:** an empty result from a `RegisterNatives` hook does *not* mean there is
no dynamic registration. It usually means you were late.

### 3.3 The library loaded on demand

Some apps load their protected library later — on a login, a payment, or after a download. For those,
attaching is fine. Distinguish the two cases by watching `dlopen`:

```javascript
// frida -U -n com.example.target -l when.js
['android_dlopen_ext', 'dlopen'].forEach(function (n) {
  const a = Module.findExportByName(null, n);
  if (a) Interceptor.attach(a, {
    onEnter(args) { this.p = args[0].isNull() ? '' : args[0].readCString(); },
    onLeave(r) { if (!r.isNull()) console.log('[dlopen] ' + this.p); }
  });
});
```

If the interesting `.so` appears in that log *after* you attached, you can still catch its
registration.

### 3.4 The fallback route

Some ART builds do not export a `RegisterNatives` symbol the script recognises. Force the fallback and
confirm it works:

```javascript
// frida — comment out the symbol route in the script, or do it by hand:
const env = Java.vm.getEnv();
const table = env.handle.readPointer();          // JNINativeInterface*
const slot = table.add(215 * Process.pointerSize); // index 215 -> RegisterNatives
const fn = slot.readPointer();
console.log('RegisterNatives = ' + fn + ' = ' + DebugSymbol.fromAddress(fn));
Interceptor.attach(fn, {
  onEnter(args) { console.log('count=' + args[3].toInt32()); }
});
```

Answer in writing: why `215 * pointerSize`? Where does 215 come from, and what are the four entries
before index 4?

<details>
<summary>Answer</summary>

`JNINativeInterface` is a struct of function pointers whose order is fixed by the JNI specification.
It begins with **four reserved pointers**, so the first real function (`GetVersion`) is at index 4.
Counting forward through the class, exception, reference, method, field, string and array groups puts
`RegisterNatives` at index 215. On 64-bit that is byte offset `215 × 8 = 0x6b8`. See
[§3.11](../README.md#311-the-function-table-index-by-index).

</details>

### 3.5 Watch for re-registration

Leave the hook running and exercise the app fully. Protectors sometimes register a stub first and
re-register the real implementation later, or re-register after an integrity check passes.

```bash
# host — count registrations per method
frida -U -f com.example.target -l ../scripts/dump-registernatives.js --no-pause \
  | tee reg.log
grep -c '^\[jni\]' reg.log
sort reg.log | uniq -c | sort -rn | head
```

A method appearing twice with two different addresses is a very strong signal, and the *second*
address is the one that matters.

---

## Part 4 — Hook what you recovered

```javascript
// frida -U -f com.example.jnidemo -l hook-recovered.js --no-pause
'use strict';

const OFFSET = 0x0;    // <- paste the offset dump-registernatives.js printed for `check`

function whenLoaded(name, cb) {
  const m = Process.findModuleByName(name);
  if (m) { cb(m); return; }
  const dl = Module.findExportByName(null, 'android_dlopen_ext');
  Interceptor.attach(dl, { onLeave() {
    const mm = Process.findModuleByName(name);
    if (mm) cb(mm);
  }});
}

whenLoaded('libguard.so', function (m) {
  const target = m.base.add(OFFSET);
  Interceptor.attach(target, {
    onEnter(args) {
      // check(Ljava/lang/String;)Z on an INSTANCE method:
      //   args[0] JNIEnv*   args[1] jobject   args[2] jstring tag
      const env = Java.vm.getEnv();
      const p = env.getStringUtfChars(args[2], null);
      console.log('[check] tag = ' + p.readCString());
      env.releaseStringUtfChars(args[2], p);
    },
    onLeave(retval) {
      console.log('[check] -> ' + (retval.toInt32() ? 'true' : 'false'));
      // retval.replace(ptr(1));    // force it
    }
  });
});
```

Or use the tracer, which does the decoding from the signature for you:

```javascript
// ../scripts/jni-arg-tracer.js -- edit TARGETS to:
var TARGETS = [
  { module: 'libguard.so', offset: 0x0 /* yours */, label: 'check',
    sig: '(Ljava/lang/String;)Z', static: false }
];
```

> **Success criterion for Parts 3–4.** You recovered all three methods, hooked one by
> module+offset, printed its real argument, and changed its return value.

---

## Part 5 — Recover it statically, from `JNI_OnLoad`

The runtime route always works. The static route is faster when it works, and knowing both tells you
which one a given target defeats.

### 5.1 Find the call

```bash
# host
readelf --dyn-syms -W libguard.so | grep JNI_OnLoad
objdump -d --start-address=0x... libguard.so | head -80     # or open it in Ghidra
```

### 5.2 In Ghidra

Follow [57 Ghidra §3.8–§3.9](../../57-Ghidra/README.md). The short version:

1. Import `libguard.so`. Analyse with defaults.
2. Import a JNI type archive (or parse the NDK's `jni.h`) so `JNIEnv` is a known type.
3. Open `JNI_OnLoad` from *Symbol Tree → Exports*.
4. Set its signature: `jint JNI_OnLoad(JavaVM *vm, void *reserved)`.
5. Find the `RegisterNatives` call. Unretyped it looks like
   `(**(code **)(*(long *)env + 0x6b8))(env, clazz, table, 3)`. Retyped it says `RegisterNatives`.
6. **The third argument is the table address, the fourth is the count.** On ARM64 that is `x2` and
   `x3` at the call site.
7. Navigate to the table. Apply the `JNINativeMethod` type, or create a structure of three pointers
   and apply it as an array of `count`.

Ghidra's `57-Ghidra/scripts/RecoverRegisterNatives.py` automates steps 5–7.

### 5.3 Where the static route fails

Try it against `../examples/dynamic_registration.c`, which is deliberately built to defeat it:

| Defence in the example | Effect on the static route | Effect on the runtime route |
|---|---|---|
| Class name XORed in `.rodata` | Intended: `FindClass`'s argument is not a readable string. **Actually: defeated at `-O2`**, where clang folds the decode and writes `com/example/jnidemo/Guar` verbatim (Part 2) | None: the decoded string is passed to ART |
| Method names assembled with `snprintf` | Holds. The table's `name` pointers point at `.bss`, which is empty on disk; only the fragments `ch`, `eck`, `se`, `al`, `native`, `Init` are visible, unpaired | None |
| Signatures assembled at runtime | Partial. `(L%s/%s/String;)Z` is a template, but the un-assembled `(Z)V` from the `GetMethodID` call site is plainly readable | None |
| Implementation functions `static` | Holds. No symbol to jump to | None: you get the address directly |
| Table filled in at runtime | Holds. **The table is all zeros in the file** | None |

Three of five hold; two leak, and neither leak is visible from the source. That ratio is the real
argument for the runtime route — not that static analysis fails completely, but that you cannot tell
*which* parts of it failed without building and reading the artefact.

That last row is the decisive one. Look at the table's file contents:

```bash
# host — the table lives in .bss / .data; on disk it may be zeros
readelf -S -W libguard.so | grep -E '\.bss|\.data'
```

**Write the conclusion in your own words.** It should be close to: static recovery reads a table that
the program has not built yet; runtime recovery reads the arguments the program actually passed.

### 5.4 The intermediate case

Most real libraries are *not* this hostile. A plain `static const JNINativeMethod kMethods[] = {...}`
sits in `.data.rel.ro` fully initialised, and the static route recovers it in two minutes. Learn to
tell the two apart quickly:

```bash
# host — does the file contain readable method-name-shaped strings near
# readable descriptor-shaped strings?
strings -a -t x libguard.so | grep -E '^\s*[0-9a-f]+ \([A-Z\[L]' | head
```

If yes, take the static route. If no, do not waste an hour on it.

---

## Part 6 — Rebase and read the function

### 6.1 Get the load base at runtime

```javascript
// frida
const m = Process.findModuleByName('libguard.so');
console.log(m.name + '  base=' + m.base + '  size=' + m.size + '  path=' + m.path);
```

### 6.2 Convert a runtime address to a file offset

```text
file_offset_in_the_image = runtime_address - module_base
```

That value is what you type into Ghidra's *Go To* (`G`) **if** Ghidra's image base is 0, which it is
by default for a shared object. If you changed the image base, subtract accordingly.

### 6.3 Confirm you landed on the right function

Three checks, all cheap:

1. The function takes at least two pointer-shaped arguments (`JNIEnv*`, then the receiver).
2. It makes calls through `param_1`'s table — the `(**(code **)(*(long *)param_1 + 0x...))` shape.
3. The offsets used match what the signature implies. A method taking a `jstring` will call
   `GetStringUTFChars` at `0x548`; one taking a `jbyteArray` will call `GetByteArrayElements` at
   `0x5c0` or `GetByteArrayRegion` at `0x640`.

### 6.4 Set the signature

```c
// Ghidra: Edit Function Signature
jboolean guard_check(JNIEnv *env, jobject thiz, jstring tag)
```

Now the decompilation is readable and you can do the actual analysis.

---

## Part 7 — Do it against a real target

Take the app you triaged in Part 1 and run the full sequence:

1. `jni-triage.sh` → report 5 lists the unaccounted-for methods.
2. `dump-registernatives.js` with `-f` → the mapping.
3. Diff: does every method from report 5 now have an address?
4. Anything still missing → it is either never called, or bound by a mechanism you have not found.
   Both are worth a paragraph.
5. Pick the most interesting method by name and signature, hook it, and log its arguments.
6. Rebase into Ghidra and read it.

**Deliverable:** a one-page map of the target's native surface.

```text
target: com.example.target
libguard.so  base at runtime 0x7xxxxxxxxx
  com.target.a.b.c   (obfuscated class -- dynamic registration permitted the rename)
    a   (Ljava/lang/String;)Z          libguard.so+0x4a18   -> attestation check
    b   ([B)[B                          libguard.so+0x4c80   -> request signing
    c   ()J                             libguard.so+0x5010   -> init, returns a handle
observations:
  - registered twice; the second address for `b` is the live one
  - `b` calls HMAC_Init_ex in libcrypto.so -> key is recoverable at that boundary
open questions:
  - what feeds `a`'s tag argument?
```

---

## Hints

<details>
<summary>Hint 1 — the script prints "No known art::JNI RegisterNatives symbol"</summary>

Expected on some builds. It falls back to the function-table slot automatically. If both fail, hook
the target library's `JNI_OnLoad` (it is exported) and read `x2`/`x3` at the `RegisterNatives` call
site yourself, or use `Stalker` to trace `JNI_OnLoad`.

</details>

<details>
<summary>Hint 2 — the class name prints as &lt;unknown class&gt;</summary>

`classNameOf` calls back into Java, which can fail very early in process life. The names, signatures
and addresses are still correct — only the class attribution is missing. Cross-reference with the DEX
inventory: match on the method name and signature.

</details>

<details>
<summary>Hint 3 — I get an address with "NO MODULE"</summary>

That is a *finding*, not an error. The implementation is in anonymous executable memory: a packer
decrypted code into a fresh mapping rather than loading a real library. Dump the region
(`Memory.readByteArray(range.base, range.size)`), write it to a file, and load it into Ghidra as raw
ARM64. Chapter [40 Obfuscation](../../40-Obfuscation/README.md) Lab 04 covers unpacking properly.

</details>

<details>
<summary>Hint 4 — my hook by offset crashes immediately</summary>

Most likely the library was not loaded when you computed `base`, so `base` was wrong. Use the
`whenLoaded` helper. Second most likely: you used the offset from a *different ABI's* library.

</details>

<details>
<summary>Hint 5 — the app detects Frida and exits</summary>

Very likely, since apps that bother with dynamic registration often bother with anti-instrumentation.
Chapters [38 TamperDetection](../../38-TamperDetection/README.md) and
[67 BypassingProtections](../../67-BypassingProtections/README.md) cover this. For this lab, the
relevant point is that the check itself usually runs in `JNI_OnLoad` — so hook `dlopen`'s return and
neutralise it *before* ART calls `JNI_OnLoad`.

</details>

---

## Success criteria

| # | Criterion |
|---|---|
| 1 | You identified a dynamically-registering library from the APK alone |
| 2 | You recovered the complete name/signature/address mapping at runtime |
| 3 | You demonstrated that attaching (rather than spawning) recovers nothing, and can say why |
| 4 | You used the function-table fallback route and can explain the index 215 |
| 5 | You hooked a recovered method by module+offset and read a real argument |
| 6 | You attempted the static route and can state precisely which defence defeated it |
| 7 | You rebased an address into a disassembler and confirmed you landed on the right function |
| 8 | You can explain in one sentence why obfuscation cannot defeat the runtime route |

---

## The sentence to be able to say

> Obfuscation can hide where the code is and what it is called. It cannot hide the moment the code
> talks to the runtime, because at that moment it must present plaintext class names, method names
> and signatures to ART. `RegisterNatives` is a mandatory chokepoint, and that is why the runtime
> route always works.

---

## Next

[Lab 04 — CTF: The Unlisted Number](lab-04-ctf-the-unlisted-number.md)
