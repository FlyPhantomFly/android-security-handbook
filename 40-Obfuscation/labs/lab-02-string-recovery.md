# Lab 02 — Recover Encrypted Strings, Then Read the Code

**Difficulty:** Intermediate
**Time:** 2–4 hours
**Prerequisites:** [Lab 01](lab-01-obfuscation-triage.md) with variant C built,
[Chapter 40 §3.2](../README.md#32-string-encryption) and
[§6.1 Phase 4](../README.md#phase-4--recover-strings-first),
[53-Frida](../../53-Frida/README.md), [56-JADX](../../56-JADX/README.md)

---

## Objective

Take an app whose strings are encrypted and whose names are gone, and turn it back into something you
can read. Specifically:

1. Find the decryptor **without knowing anything about the algorithm**.
2. Exhaust it, so you recover strings from code paths you never executed.
3. Write the recovered strings back into the Smali at their call sites.
4. Use those strings to rename classes, methods and fields semantically.
5. Produce a written model of what the app does — the deliverable that Phase 7 demands.

Then do it a second time against a harder variant with **per-class decryptors**, where the static
approach that worked the first time stops working and the dynamic one does not care.

## Why this matters

This is the flagship lab of the chapter because it is the flagship *phase* of the methodology.

Section 6.1 places string recovery at Phase 4 — after unpacking, before control flow, before renaming,
before everything else — and the justification is a single observation:

> After identifier renaming, **strings are the only remaining semantics**.

A method called `a` that contains `"/v2/payments/authorize"` is not called `a` any more. It is
`authorizePayment`. You now know that, you can rename it, and every caller of it becomes partly
understood too. Strings are the seeds from which the naming of the entire program regrows.

Which is why doing them first is not a stylistic preference. It changes what you have to do next:

- It often makes control-flow work **unnecessary**, because once you can grep for `/v2/transfer` you
  land directly in the one method you care about instead of deflattening forty you do not.
- It converts an unreadable program into a merely difficult one, and difficulty is a resource problem
  rather than a capability problem.
- It produces the findings. Endpoints, credentials, crypto configuration, and root-check paths are
  four buckets of report material that come out of a string dump for free.

The second lesson is the *universal counter*, and it is the most transferable idea in reverse
engineering:

> The decrypted string must exist in memory for the program to use it. Therefore there is always a
> moment, and always a specific function, at which plaintext exists. You do not need to break the
> cipher. You need to be present at that moment and write down what you see.

That principle applies unchanged to packers, signature checks, licence validation and native code. If
you take one thing from this chapter, take that.

---

## Setup

You need variant C from [lab 01](lab-01-obfuscation-triage.md) — renamed, with XOR-encrypted strings.
If you skipped it, the complete implementation including the ciphertext generator is in
[`../examples/StringEncryption.java`](../examples/StringEncryption.java) and [`../examples/gen-string-table.py`](../examples/gen-string-table.py).

```bash
# host
adb install -r C.apk
adb shell am start -n com.obflab.target/.MainActivity

# confirm the problem before you start solving it
unzip -p C.apk classes.dex | strings -n 6 | grep -c 'https\?://'   # expect 0
apktool d -f -o C_out C.apk >/dev/null
jadx -d C_jadx --no-res C.apk >/dev/null 2>&1
```

Frida must be working:

```bash
# host
frida-ps -U | head
```

---

## Steps

### Step 1 — Confirm what you are facing, and resist the urge to read code

```bash
# host
unzip -p C.apk classes.dex | strings -n 6 | grep -E 'obflab|sk_live|/auth|/payments'
grep -rn 'xor-int' C_out/smali*/ | head
```

**Q1.** How many of the six interesting strings are readable? What *is* readable in the string pool,
and why did those particular things survive?

**Q2.** You have found a method with `xor-int/lit8` in a loop. Before you reverse-engineer it: is
reading this method the fastest route to the strings? Argue both sides, then commit to an answer.

### Step 2 — Find the decryptor without reading it

The universal finder. It does not care about the algorithm, because it hooks the **result**.

```bash
# host — spawn PAUSED. Decryptors frequently run from static initialisers.
frida -U -f com.obflab.target -l ../scripts/frida-string-decryptor.js --pause
```

In the REPL:

```
%resume
```

Let the app run for twenty seconds, then:

```
sd.candidates()
```

**Q3.** Which method tops the list? How many Strings did it construct, and how does that count compare
with the next application-package entry?

**Q4.** Read the hook in the script that produced this ranking. Precisely *why* does hooking
`java.lang.String.<init>([B)` catch a decryptor whose cipher you know nothing about? Name one
plausible decryptor design it would **miss**, and say what you would do about it.

**Q5.** Frames from `java.`, `android.`, `kotlin.` and `com.google.android.gms.` are filtered out of
the ranking. What would the output look like without that filter, and why is the filter a *heuristic*
rather than a correctness fix?

### Step 3 — Learn the signature, then exhaust it

```
sd.inspect("com.obflab.target.S")
```

**Q6.** What is the exact signature? How many overloads are there? What would have happened if you had
guessed one and hooked it, and how would that failure have looked?

```
sd.exhaust("com.obflab.target.S", "a", 0, 512)
sd.stats()
```

**Q7.** How many strings did `exhaust` recover? How many had `harvest` seen? Name a specific string
that only `exhaust` found, and explain — from the source you wrote in lab 01 — why the passive
approach could never have seen it.

**Q8.** The exhaust loop catches and ignores exceptions. What throws, why, and what would you conclude
if *every* index threw?

**Q9.** `exhaust` actually executes application code. Name two ways that could go wrong on a real
target, and state when in your session you would therefore run it.

### Step 4 — Triage the dump

```
sd.grep("http")
sd.grep("key|token|secret|bearer")
sd.save()
```

```bash
# host
adb pull /data/local/tmp/strings-dump.json .
adb pull /data/local/tmp/strings-dump.txt .
grep -Ei 'https?://|/api/|/v[0-9]+/' strings-dump.txt
grep -Ei 'key|secret|token|password|auth|bearer' strings-dump.txt
grep -Ei 'AES|RSA|HMAC|SHA|PBKDF|ECB|CBC|GCM' strings-dump.txt
```

**Q10.** Which of the four triage buckets produced report-worthy material? Write the credential finding
as one sentence, and state what evidence you would attach.

**Q11.** You recovered the endpoint `/payments/transfer`. What is the *next* question you ask about it,
and why is it not a question about obfuscation at all?

### Step 5 — Write the strings back into the code

A flat list of strings is a haystack. The same strings at their call sites are a map.

```bash
# host — dry run first, always
python3 ../scripts/annotate-smali-strings.py --smali C_out --json strings-dump.json --triage

# then apply
python3 ../scripts/annotate-smali-strings.py --smali C_out --json strings-dump.json --write --backup

# and read the result
grep -rn '\[str\]' C_out/smali*/com/obflab/ | head -40
grep -rniE '\[str\].*(api|token|transfer|login)' C_out/smali*/
```

**Q12.** How many call sites were annotated, and how many were unresolved? Look at three unresolved
ones — what do they have in common?

**Q13.** The script tracks registers with a simple linear scan inside each method. Construct a concrete
Smali example it would get **wrong** — not merely fail on, but silently annotate incorrectly. Then
explain why the script reports unresolved sites instead of guessing.

**Q14.** With the Smali annotated, find the method that performs the transfer. How long did that take
compared with your estimate before you had the strings?

### Step 6 — Semantic renaming

Open `C.apk` in `jadx-gui` and rename from evidence, using the table in
[§6.1 Phase 6](../README.md#phase-6--semantic-renaming).

Rename at minimum:
- the class holding the HTTP logic
- its `login` and `transfer` methods
- the field holding the API key
- the decryptor class and method

**Q15.** After renaming five things, how many *other* classes became partly readable? Describe the
compounding effect in your own words.

**Q16.** `jadx-gui` persists renames in a `.jobf` file. Why does the chapter tell you to commit that
file to your engagement notes?

**Q17.** Which renames were derived from strings, and which from *other* survivors — the manifest,
framework calls, annotations? List one of each and name the survivor category it came from.

### Step 7 — Write the model

Phase 7. In prose, in your notes, not in your head:

- What does this app do?
- Which classes implement it?
- Where are the trust boundaries?
- What have you **not** looked at?

**Q18.** Writing that down surfaced a gap. What was it? (If it did not, you wrote it too briefly —
try again with the "what have I not looked at" section first.)

### Step 8 — The harder variant: per-class decryptors

Now rebuild variant C with a *different* decryptor in every class, each with its own key. The pattern
is in [§3.2 variant C](../README.md#variant-c--per-class-decrypt-methods) and a generator is in
[`../examples/StringEncryption.java`](../examples/StringEncryption.java) and [`../examples/gen-string-table.py`](../examples/gen-string-table.py).

```bash
# host
./build-variant-C2.sh          # or rebuild by hand with per-class keys
adb install -r C2.apk
grep -rn 'xor-int' C2_out/smali*/ | wc -l
```

**Q19.** How many decryptors are there now? What does that do to the *static* approach you considered
in Q2 — reading the algorithm and reimplementing it in Python?

**Q20.** Run the same script, unchanged, against C2. Does `sd.candidates()` still work? Explain
precisely why the number of decryptors is irrelevant to it.

**Q21.** `exhaust` needs a class and a method name. With four hundred decryptors, how do you exhaust
them all? Write the loop. (Hint: `sd.candidates()` gives you the class names; `sd.inspect` gives you
the signatures; `Java.enumerateLoadedClasses` gives you the rest.)

**Q22.** Compare the total time for C and C2. What does the ratio tell you about the value a developer
gets from moving to per-class decryptors, and what would you tell them?

---

## Hints

<details>
<summary>Hint — Q3, nothing appears in candidates()</summary>

In order:

1. Did you `%resume`? The script installs hooks and waits; if you never resumed, no app code ran.
2. Did you exercise the app? Static initialisers run on first class use, which may need a tap.
3. Is the app packed? A stub has no strings worth recovering — unpack first
   ([lab 04](lab-04-unpack.md)).
4. Does the decryptor build its output through `StringBuilder` rather than `new String(byte[])`? Try
   `sd.discoverBuilders()`.
</details>

<details>
<summary>Hint — Q6, the overload trap</summary>

```
sd.inspect("com.obflab.target.S")
```

prints every `String`-returning method with its full signature. If a class has six methods named `a`,
hooking the wrong one installs successfully and never fires — and the symptom is identical to "the
decryptor is somewhere else", which is why people waste an hour here.
</details>

<details>
<summary>Hint — Q21, exhausting many decryptors</summary>

```javascript
// Frida REPL — enumerate app classes, find String-returning static methods
// taking a single int, and exhaust each one.
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (name.indexOf("com.obflab.target") !== 0) return;
            var C;
            try { C = Java.use(name); } catch (e) { return; }
            var methods;
            try { methods = C.class.getDeclaredMethods(); } catch (e) { return; }
            for (var i = 0; i < methods.length; i++) {
                var sig = methods[i].toString();
                if (sig.indexOf("java.lang.String ") === -1) continue;
                if (sig.indexOf("(int)") === -1) continue;
                sd.exhaust(name, methods[i].getName(), 0, 256);
            }
        },
        onComplete: function () { sd.save(); }
    });
});
```

Note what this does *not* need: any knowledge of the keys, the algorithms, or how many there are.
</details>

---

## Solution

<details>
<summary>Answers Q1–Q2 — what you are facing</summary>

**Q1.** Zero of the six. What remains readable is everything from the *survivors* table in
[§3.1](../README.md#31-identifier-renaming): framework class and method descriptors
(`Ljava/lang/String;`, `Landroid/app/Activity;`), the manifest component name `MainActivity`, resource
names, and any string the obfuscator's transform did not cover — commonly log tags, exception
messages the developer excluded, and third-party library strings.

They survived because they are not the app's own string literals: framework descriptors are structural
parts of the DEX that the runtime resolves by name, and manifest-referenced names must match the
manifest.

**Q2.** Both sides honestly:

*For reading it:* the algorithm is a single XOR with a literal key. Twenty lines of Python and you can
decrypt every array offline, with no device, no root and no Frida. That is genuinely fast **here**.

*Against:* it does not generalise. The moment the key becomes position-dependent, or the cipher becomes
AES, or there are four hundred decryptors instead of one (step 8), the static route's cost grows while
the dynamic route's cost stays flat at "run one script". You are also reimplementing, and a
reimplementation can be subtly wrong in ways a dump cannot.

**Commit:** dynamic first, always, when you can run the app. Section 6.1 Phase 2 says so, and the
reason is that every protection in this chapter is stronger against static analysis than dynamic,
because every protection must be undone at runtime by the program itself. Keep the static route for
when you cannot run the target — malware you refuse to execute, or an app with anti-analysis you have
not yet defeated.
</details>

<details>
<summary>Answers Q3–Q5 — finding the decryptor</summary>

**Q3.** `com.obflab.target.S.a` (or whatever R8 renamed it to) tops the list, typically with several
dozen constructions against low single digits for anything else in the app's packages. The gap is
usually an order of magnitude, which is what makes the ranking decisive rather than suggestive.

**Q4.** Because **every** string-decryption routine, whatever its cipher, must end by turning
plaintext bytes or chars into a `java.lang.String`. That is not a property of the algorithm; it is a
property of the Java type system. XOR, AES, RC4, a custom stream cipher, a whitebox implementation,
per-class variants — all of them converge on the same constructor, and frame 1 of the stack at that
moment is the decryptor.

That is the universal counter restated as a hook: you are not attacking the cipher, you are standing
at the exit.

What it would miss: a decryptor that returns `char[]` or `byte[]` and lets the *caller* build the
String; or one that assembles output through `StringBuilder`; or one implemented in native code that
returns a `jstring` built with `NewStringUTF` (which does not go through the Java constructor at all).
What to do: `sd.discoverBuilders()` for the StringBuilder case, and for the native case hook
`NewStringUTF` in the JNI function table or `frida-trace -i 'Java_*'` at the JNI boundary.

**Q5.** Without the filter the top entries would be framework internals — charset decoding, JSON
parsing, resource loading, `Okio`/`OkHttp` buffers — constructing thousands of Strings and drowning
the app's decryptor entirely.

It is a heuristic, not a correctness fix, because an obfuscator can place its runtime class in a
package that *looks* like a framework package precisely to exploit this. If discovery finds nothing,
widen the filter before concluding the decryptor is native. The rule generalises: any filter that
makes output readable also makes output incomplete, and you must know which of the two you currently
need.
</details>

<details>
<summary>Answers Q6–Q9 — exhausting it</summary>

**Q6.** `public static java.lang.String com.obflab.target.S.a(int)` — one overload in this build. On a
real target expect several methods named `a` with different signatures.

Hooking the wrong overload installs without error and never fires. The symptom is a silent absence of
output, which is indistinguishable from "the decryptor is elsewhere", "the code path did not run" and
"my script is broken". That ambiguity is why `sd.inspect` exists and why guessing is not acceptable
practice.

**Q7.** `exhaust` recovers everything in the index space — in this build, all seven strings.
`harvest`, during a passive run of a app that only shows one screen, sees perhaps two.

The specific example: the transfer endpoint `/payments/transfer` and the API key are inside the
`if (System.currentTimeMillis() == 1L)` block in `MainActivity`, which never executes. A passive hook
can only report decryptions that happened, and that one never happens.

That gap is not artificial. On a real target the strings you most want — debug endpoints, fallback
hosts, error-path credentials, admin paths — live precisely in code you will never trigger by tapping
around. `exhaust` is the difference between a sample and a census.

**Q8.** `ArrayIndexOutOfBoundsException` for indices past the end of the ciphertext table, and
whatever the decryptor throws for malformed input. Both are expected and both are ignored.

If *every* index threw: you have the wrong method, the wrong argument order (the index may not be the
first parameter), or the class was not initialised — some decryptors populate their table in a static
initialiser that has not run yet. Touch any field of the class first to force initialisation, then
retry.

**Q9.** Two ways it goes wrong on a real target:

1. **Side effects.** Some decryptors update a cache, bump a counter, or lazily initialise state that
   other code depends on. Calling one four thousand times can leave the app in a state it never
   reaches naturally.
2. **Detection.** An app doing integrity or behaviour monitoring may notice several thousand calls to
   an internal method in a hundred milliseconds. That is not a normal execution profile.

Therefore: exhaust **late** in your session, after you have collected everything else you need from
that process, and preferably in a process you are happy to discard and restart.
</details>

<details>
<summary>Answers Q10–Q11 — triage</summary>

**Q10.** The credentials bucket. The finding:

> The application embeds a live API credential (`sk_live_51H8xQz…`) which is obfuscated at rest by a
> fixed-key XOR routine and reconstructed in memory at runtime. The credential was recovered in
> approximately three minutes using standard instrumentation; the obfuscation delays but does not
> prevent recovery. The credential must be treated as public and the design changed so that no
> credential capable of authorising a privileged operation is distributed to clients.

Evidence to attach: the recovered plaintext (redacted appropriately for the report), the exact command
that recovered it, the elapsed time, and the annotated Smali showing the call sites that consume it.
The elapsed time matters more than people expect — it is what converts an abstract "obfuscation is not
security" argument into a number a risk owner can act on.

**Q11.** The next question is: **what does that endpoint authorise, and does the server check anything
beyond the credential you just recovered?** Replay a request to it with the recovered key from a plain
HTTP client with no app at all, and see what happens.

It is not a question about obfuscation because obfuscation was never the control. It was the
*delivery* of an ineffective control. The string recovery is the step that lets you ask the real
question, which is about server-side authorisation — and that is where the finding with impact lives.
</details>

<details>
<summary>Answers Q12–Q14 — annotation</summary>

**Q12.** In this build essentially every call site resolves, because each is a `const/16` immediately
followed by the `invoke-static`. Unresolved ones typically share one property: **the argument does not
arrive as a literal in the same basic block.** It comes from a loop variable, a field, an array
element, or another method's return value.

**Q13.** A case it would get silently wrong:

```smali
    const/16 v0, 0x2f

    if-eqz p1, :cond_0
    const/16 v0, 0x31        # reassigned in a branch the scanner does not model
    :cond_0

    invoke-static {v0}, Lcom/obflab/target/S;->a(I)Ljava/lang/String;
```

A linear scan remembers the *last textual* assignment, `0x31`, and annotates with string 49 — but at
runtime the value depends on `p1`, and half the time it is string 47. The annotation is confidently
wrong.

Why the script reports unresolved rather than guessing: **a wrong annotation is worse than no
annotation**, because you will trust it. Annotations you believe are load-bearing for every conclusion
you draw afterwards, and a single confident falsehood propagates through an entire analysis. The
script's honesty about its own limits is the feature; the header says so explicitly, and when a value
matters you confirm it dynamically with `sd.harvest()`.

**Q14.** After annotation: seconds, with one grep.

```bash
grep -rn '\[str\].*payments/transfer' C_out/smali*/
```

Before annotation, with names gone and strings encrypted, the honest estimate is tens of minutes of
reading — and that is for a toy app with a dozen classes. On a real target with four thousand classes
the difference is between an afternoon and a grep. That ratio is the entire argument for Phase 4's
position in the methodology.
</details>

<details>
<summary>Answers Q15–Q18 — renaming and the model</summary>

**Q15.** Renaming five things typically makes ten to twenty others partly readable, because renaming
propagates through *use*: once `S.a(int)` is `decrypt(int)`, every call site reads as a string lookup;
once the HTTP class is `ApiClient`, every field of type `ApiClient` names itself; once `transfer` has
its name, its caller is the payment flow.

The compounding is the point. Each rename is not one unit of understanding, it is one unit plus a
fraction of every neighbour. Skipping Phase 6 is the difference between "I looked at it" and "I
understand it", and it is skipped constantly because it feels like clerical work rather than analysis.

**Q16.** Because it is the closest thing to a deobfuscated build you will ever have, and it represents
hours of judgement that cannot be regenerated automatically. Committing it means a colleague inherits
your understanding rather than repeating your work, and it means *you* inherit it when the client
ships a new version six months later and you diff against it.

**Q17.** Examples by survivor category:

| Rename | Derived from | Survivor category |
|---|---|---|
| `ApiClient.transfer` | recovered string `/payments/transfer` | string constants |
| `MainActivity` | it is named in `AndroidManifest.xml` | manifest component names |
| `S.decrypt` | it returns `String` and is called everywhere | structure plus behaviour |
| a `Cipher`-using method → `decryptGcm` | `Cipher.getInstance("AES/GCM/NoPadding")` | framework API names |
| a field → `authToken` | assigned from `getString("auth_token", null)` | framework API + string |

The point of listing them by category is that **strings are the biggest source but not the only one**.
The survivors table is a checklist of free information, and a good analyst uses all of it.

**Q18.** The commonest gap the writing surfaces is the "what have I not looked at" section: the native
library nobody opened, the second `classes2.dex`, the exported receiver in the manifest, the
`WebView` that loads a remote URL. Those are almost always where the real finding was, and the reason
they get missed is that they were never *decided* against — they were never noticed, and
writing the model is the mechanism that notices them.
</details>

<details>
<summary>Answers Q19–Q22 — per-class decryptors</summary>

**Q19.** As many as there are classes with strings — dozens to hundreds. This is the strongest common
variant, and it is specifically designed to break the static route: reading and reimplementing one
algorithm is a twenty-minute job; doing it four hundred times, each with a different key and a
slightly different algorithm, is not a job anyone finishes.

**Q20.** Yes, unchanged, and the reason is worth stating precisely: the discovery hook is on
`java.lang.String.<init>`, which is a **single choke point that every decryptor must pass through**.
Four hundred decryptors produce four hundred entries in the caller ranking; the script does not care
how many there are because it never needed to know about any of them individually.

This is the general shape of a good counter-technique: find the place the design *must* converge, and
stand there. Multiplying the number of decryptors multiplies the defender's build complexity and does
not multiply your cost at all.

**Q21.** See the hint. The loop enumerates loaded classes in the app's packages, reflects over their
methods for `String`-returning candidates, and exhausts each. Written once, it works on every target
with this design. On a real app you would also want to restrict the index range per class (most
per-class tables are small) and to write incrementally, because a full sweep can produce tens of
thousands of strings.

**Q22.** Variant C: perhaps twenty minutes end to end. Variant C2: perhaps twenty-five, and most of the
extra is waiting for the sweep to finish rather than thinking.

What that tells a developer:

> Moving from a single global string decryptor to per-class decryptors substantially increases build
> complexity and binary size, and raised the recovery time in our assessment from approximately twenty
> minutes to approximately twenty-five. It defeats a naive static reimplementation, which is a real
> benefit against low-effort attackers, and it does not affect a dynamic recovery at all, because
> every variant converges on the same `String` constructor. If the objective is to protect the values
> currently held in these strings, the effective control is not to ship them: the API credential
> recovered in this assessment should be replaced with a server-mediated flow rather than obfuscated
> more thoroughly.

Note the shape of that advice. It does not say "obfuscation is pointless"; it prices it honestly and
then redirects the budget to the thing that changes the outcome.
</details>

---

## Success criteria

- [ ] You confirmed zero readable URLs and identified what *did* survive, by survivor category
- [ ] You argued both sides of static-versus-dynamic and committed to an answer with a reason
- [ ] You found the decryptor with the universal finder, without reading its algorithm
- [ ] You can explain why hooking `String.<init>([B)` is cipher-independent, and name a design it misses
- [ ] You used `sd.inspect` to get the exact signature rather than guessing an overload
- [ ] You exhausted the index space and recovered at least one string that no execution path reached
- [ ] You can explain what throws during exhaustion and what it means if everything throws
- [ ] You named two ways `exhaust` can perturb a real target, and when to run it accordingly
- [ ] You produced the four triage buckets and wrote the credential finding with recovery time
- [ ] You annotated the Smali and can state the annotated-versus-unannotated ratio
- [ ] You constructed a Smali example the annotator would get silently wrong
- [ ] You found the transfer method by grepping annotations, and compared with your prior estimate
- [ ] You renamed at least five things and described the compounding effect
- [ ] You listed renames derived from strings *and* from at least two other survivor categories
- [ ] You wrote the Phase 7 model, including "what I have not looked at"
- [ ] You rebuilt with per-class decryptors and recovered them with the same script, unchanged
- [ ] You wrote the developer advice for per-class decryptors, priced honestly

---

## Next

[Lab 03 — Deflatten by hand](lab-03-deflatten.md). Now that the strings have told you *which* methods
matter, you go and read one that has been deliberately made unreadable.
