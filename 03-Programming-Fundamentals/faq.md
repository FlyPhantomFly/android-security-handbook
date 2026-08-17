# 03 — Programming Fundamentals — FAQ

The questions people actually ask, including the ones that feel too basic to ask out loud. Nobody is
born knowing this. Every one of these has been asked by someone who went on to be very good at the
job.

Section references point into [README.md](README.md).

---

## The genuinely basic ones

### 1. Do I really need to learn to program to be a pentester?

To use tools, no. To be good, yes, and the reason is specific: **your entire job is reading code
other people wrote.** Not writing applications — reading, understanding, and predicting the
behaviour of an unfamiliar codebase under inputs its author did not consider.

You also need to write small things constantly: a script to decode a format, a Frida hook, a fuzzing
harness, a parser for a proprietary protocol. None of those are software engineering. They are
twenty-line programs, and being unable to write them means waiting for someone else, which means you
will not do it.

The threshold is much lower than "become a developer" and much higher than "run tools". ([1.3](README.md#13-why-a-pentester-learns-to-program-when-they-are-not-paid-to-write-software))

### 2. Which language should I learn first?

**Python**, then **Java**, then read enough **C** to be dangerous. In that order, for these reasons.

Python gets you writing useful scripts in days, and scripting is most of what you will write.
Java (and Kotlin) is what Android apps are written in, so it is what you will read every day. C is
what the interesting parts of Android are written in, and — more importantly — it is the language in
which you can *see* memory, which makes every security concept concrete.

You do not need to be *fluent* in all three. You need to be fluent in one and able to read the other
two. Reading is a much lower bar than writing, and it arrives much faster.

### 3. I read the chapter and understood it while reading, but I cannot write any code. Is that normal?

Completely normal, and it means you have done exactly half the work. Reading builds recognition;
writing builds recall, and they are different skills stored differently.

The fix is small and unglamorous: type the examples out by hand rather than copying them, break them
deliberately, and predict the error before you run it. Twenty minutes a day of that beats four hours
of reading a week. Start with [Lab 01](labs/lab-01-first-program-all-the-way-down.md).

### 4. What actually *is* a program?

A sequence of numbers in memory that a CPU interprets as instructions. That is the whole answer, and
it is worth sitting with, because everything else in this repository follows from it.

The number `0x8b000020` is an ARM64 instruction meaning "add register 0 to register 1 and put the
result in register 0". It is also just a number. If you write it into a file it is data; if the CPU's
program counter points at it, it is code. **Nothing about the bytes distinguishes the two** — the
distinction is made by the memory permissions the operating system assigns, and by where the program
counter happens to be pointing.

That is why code injection works, why `W^X` (write XOR execute) exists as a defence, and why a DEX
file can be "just data" in one moment and executing code in the next. ([1.5](README.md#15-the-one-idea-that-makes-everything-else-easy))

### 5. What is the difference between a compiler, an interpreter and a runtime?

A **compiler** translates your source into something else, once, before the program runs. An
**interpreter** reads your source and performs it directly, every time, without producing a
translated artefact. A **runtime** is the machinery that has to be present while your program runs —
memory management, type information, exception handling, the standard library.

C has a compiler and almost no runtime. Python has an interpreter and a large runtime. Java has a
compiler (to bytecode) *and* a runtime (the JVM, or ART on Android) that interprets and compiles that
bytecode further. Android has all of it at once. ([3.18](README.md#318-compilation-interpretation-bytecode-vms-jit-and-aot))

### 6. Why does everyone say memory is so important? I never think about it in Python.

Because Python is doing an enormous amount of work to let you not think about it, and every layer of
that work is somewhere a bug can live.

When you write `x = [1, 2, 3]` in Python, something allocated memory, decided how much, tracked how
many references point at it, and will free it later. In C you would do all of that by hand and could
get every step wrong. In Java the runtime does it and can only get some of it wrong.

You need to think about it because **the bugs that matter most on Android are memory bugs**, and
because when you attach a debugger or dump a heap you are looking at memory directly, with no
abstraction to hide behind. ([3.14](README.md#314-memory-management--manual-versus-garbage-collected))

### 7. Why does array indexing start at 0? It feels wrong.

Because the index is an **offset from the start**, not a count of items. Element *i* lives at
`base_address + i * element_size`. The first element is at the start, so its offset is zero.

It is not a convention someone chose. It falls out of the address arithmetic, which is also why you
will see exactly that formula in disassembly — an array access compiles to a multiply and an add.
Once you have seen `add x0, x1, x2, lsl #2` (base + index × 4) a few times, zero-based indexing stops
feeling arbitrary. ([3.9.1](README.md#391-the-array--contiguous-indexed-the-foundation-of-everything))

### 8. What is a pointer, in plain words?

A pointer is a variable whose value is **the address of another piece of memory**.

The postal analogy holds well. A normal variable is a house with something in it. A pointer is a
piece of paper with a house's address written on it. You can copy the paper (cheap) without copying
the house (expensive), several papers can name the same house, and if the house is demolished the
paper still has the address written on it — which is a use-after-free, and is why it is dangerous.

The three operations are: take the address of something (`&x` — "write down where x lives"), follow
an address (`*p` — "go to the house on this paper"), and pointer arithmetic (`p + 1` — "the next
house along"). ([3.13](README.md#313-pointers-and-references))

### 9. Java has no pointers though, right?

Java has **references**, which are pointers with the dangerous operations removed. A Java reference
holds an address, just like a pointer. You cannot do arithmetic on it, cannot make one from an
integer, cannot free what it points to, and every array access through it is bounds-checked.

So `NullPointerException` is named accurately: a reference *is* a pointer, and this one was null.
What Java removed is not the pointer, it is the ability to misuse it. ([3.13.4](README.md#3134-references-in-java--the-same-address-fewer-permissions))

### 10. Why does `0.1 + 0.2` not equal `0.3`? That seems like a bug.

It is not a bug, it is arithmetic. Floating-point numbers are stored in binary, and 0.1 has no exact
binary representation — the same way one third has no exact decimal representation, and writing
`0.3333...` forever does not fix it.

The computer stores the nearest value it can, the tiny errors compound through the addition, and the
result differs from the nearest representation of 0.3 by about 5.5 × 10⁻¹⁷.

The rules that follow: never use floating point for money, and never compare floats with `==` —
compare the absolute difference against a small tolerance. ([3.2](README.md#32-primitive-types--sizes-signedness-and-why-you-must-memorise-them))

### 11. Why do I have to memorise how many bits an `int` is? Can I not just look it up?

Because you need it *while reading*, not while writing. When you see `int size = count * 16` in a
decompiled parser, the thought "32 bits, signed, wraps at 2 147 483 647, so a `count` above about
134 million overflows" has to happen automatically, in the same second you read the line. If you have
to look it up, you will not look it up, because at that moment you do not yet know the line is
interesting.

It is four numbers. `byte` 8, `short` 16, `int` 32, `long` 64, all signed in Java. Learn them once.
([3.2.1](README.md#321-the-table-you-should-know-cold))

### 12. What is the difference between `=` and `==`?

`=` **assigns** — it puts a value into a variable. `==` **compares** — it asks whether two things are
equal and produces true or false.

`if (x = 5)` in C assigns 5 to x and then tests whether 5 is true, which it is, so the branch always
runs. That is a real, historically significant class of bug; it is why some people write
`if (5 == x)` and why every modern compiler warns about it.

In Java, `==` on objects compares **references** — whether they are the same object — not contents.
For strings you must use `.equals()`. This bug hides brilliantly, because string *literals* are
interned so `"a" == "a"` is true, and the code works right up until the string is built at runtime.

### 13. What is `null`, and why is it such a big deal?

`null` is a reference that points at nothing. It exists because sometimes there genuinely is no
object — no user is logged in, the file was not found, the list is empty.

It is a big deal because it is a value that fits everywhere a real object fits, but supports none of
the operations. So the type system says the code is fine and the runtime disagrees. Its inventor,
Tony Hoare, called it his "billion dollar mistake".

Security relevance: a null returned from a function that failed, and not checked by its caller, turns
a "could not verify" into a "verified" surprisingly often. And Kotlin's null safety — types that
cannot be null without saying so — is one of the strongest arguments for Kotlin over Java.

### 14. What is the difference between a bug, a crash and a vulnerability?

A **bug** is behaviour that differs from what was intended. A **crash** is one visible symptom of
some bugs. A **vulnerability** is a bug an attacker can *use*, and that is a strictly narrower
category than either.

The reasoning chain that turns one into another: is the buggy code reachable from something an
attacker controls? Does the attacker control the *inputs* to the bug, or only trigger it? Does
triggering it give them anything — data, a crash they benefit from, control of execution?

An integer overflow in a function that only ever receives a value from a hardcoded constant is a bug
and not a vulnerability. The same code, with the value from a network packet, is critical. This
reasoning is what severity ratings actually are. ([9.2](README.md#92-intermediate--a-planted-integer-overflow-found-four-ways))

---

## The ones that come up while working

### 15. My code does not work and I do not know why. What do I do?

In this order, and stop as soon as it works.

**Read the error message.** All of it, including the last `Caused by`. Beginners skim errors; the
error usually contains the file, the line and the reason.

**Print the values.** Not "it got here" — the actual values of the variables involved. Half of all
bugs are "the value was not what I assumed", and one print reveals it.

**Bisect.** Comment out half. Still broken? The bug is in the remaining half. Halve again. Ten steps
finds one line in a thousand.

**Use a breakpoint.** A debugger shows you *every* local at once, and you can step. Print debugging
shows you the one variable you thought to print, and you get one guess per rebuild.

**Explain it out loud**, to a colleague or an inanimate object. Articulating an assumption is
frequently enough to notice it is false. This is not a joke; it is the single highest-yield technique
on the list.

**Quit thinking and look.** ([7.1](README.md#71-debugging-as-a-skill-not-a-tool))

### 16. Print debugging feels faster than setting up a debugger. Is it?

For the first ten minutes, genuinely yes — and that is why the habit sticks.

After that it is dramatically slower, and the reason is that each print is a **guess**. You guess
which variable matters, rebuild, run, discover you guessed wrong, add another print, rebuild, run.
Each cycle is a rebuild plus a re-run plus a re-trigger of the bug.

A breakpoint shows you every local variable in scope, the full call stack, and lets you step forwards
one line at a time — all without guessing and without rebuilding. And a **watchpoint** (`watch x` in
gdb) breaks the moment a value changes, which answers "what is corrupting this?" — a question print
debugging cannot answer at all.

Use both. Print debugging is always available, works in production, works across processes and works
where you cannot attach. Breakpoints are for when you are actually confused. The mistake is using
only the first. ([7.1.1](README.md#711-print-debugging--underrated-always-available), [7.1.2](README.md#712-breakpoints-and-stepping))

### 17. How do I read a stack trace?

Three steps, and the first is the one people skip.

**Read the last `Caused by` first.** That is the root cause. Everything above it is consequence.

**Then find the topmost frame in a package you own.** Framework frames above it are transport. That
frame is where the failure became visible — which is often *not* where the bug is.

**Then read the exception message.** It usually names the exact method and the exact null.

The mental model: an exception unwinds the stack, and each layer that catches and rethrows adds a
`Caused by`. So the chain is a history, printed newest first. Read it backwards.
([3.17.5](README.md#3175-how-to-read-a-stack-trace))

### 18. How do I start reading a codebase I have never seen?

Not at the top. Five moves:

1. **Entry points** — where does execution begin? On Android: the manifest's exported components,
   deep-link handlers, JNI functions.
2. **The data** — where does it store things, what does it talk to, what crypto does it call?
3. **The state** — pick one value you care about and find where it is created, stored, read and
   destroyed. Four rows. An empty row is usually your finding.
4. **Ignore the noise** — deliberately skip bundled libraries, UI, analytics, getters. One `grep -v`
   takes 8 000 classes down to 400.
5. **Name what you learn** — a notes file, and rename classes in JADX as you understand them.

The change in mindset that makes it work: **you are building a map, not reading a book.** A book is
read once, forwards. A map is built from landmarks outwards, and its value is that you can return to
it. ([8.1](README.md#81-the-single-most-important-pentester-skill-reading-code-you-did-not-write))

### 19. Should I read the code top to bottom to understand it properly?

No, and this is the most common and most costly beginner mistake. Three hours in, you will still be
in utility classes, you will have no conclusions, and you will be exhausted.

Codebases are not narratives. They have no beginning. Start where execution starts and where your
question lives, and let the middle stay unread until something forces you into it. The parts you
never read are usually the parts that did not matter.

### 20. How do I know if code that exists actually runs?

You do not, from reading. This is a distinct question and it decides severity.

**Statically:** trace backwards from the function to something reachable — an exported component, a
public API, a callback the framework invokes. If nothing reaches it, it is dead. Check for feature
flags and build-type guards while you are there.

**Dynamically, which is definitive:** hook it and use the app.

```javascript
// Frida REPL — did it run at all?
Java.perform(function () {
  Java.use("com.target.app.Suspect").theMethod.implementation = function () {
    console.log("[+] it ran, args: " + JSON.stringify(arguments));
    return this.theMethod.apply(this, arguments);
  };
});
```

A finding in unreachable code is not a finding. A finding in code you *proved* runs is much harder to
argue with. ([11](README.md#11-common-mistakes))

### 21. The decompiled code makes no sense. Is the app obfuscated?

Maybe, but check the simpler explanation first: **decompilers guess.** They reconstruct
source-like code from bytecode, and when the original had unusual control flow, or the optimiser
rearranged it, the reconstruction can be strange without anyone intending it.

Order of investigation: read the **Smali** instead (it is a direct rendering of the bytecode and
cannot be wrong in the same way); try a second decompiler and compare; and if the class and method
names are single letters, it is obfuscation.

The rule: **the bytes are the truth.** Everything else — decompiled Java, Smali, disassembly — is a
rendering of them, and when renderings disagree, go down a level. ([6.3](README.md#63-what-obfuscation-does-and-does-not-do))

### 22. Does obfuscation make an app impossible to analyse?

No. It makes it slower, which is its actual purpose.

Obfuscation renames things the developer chose to name. It cannot rename anything that must be exact
across a boundary: framework method names (`onCreate`), JNI symbols, resource identifiers, protocol
parameter names that go on the wire, and string literals used as keys. Those survivors are anchors,
and from an anchor you find everything that touches it.

Also, renaming does not change *behaviour*. A hook on a method still fires whatever the method is
called, and dynamic analysis is largely indifferent to naming.

### 23. Everyone says "use a hash map" — what makes them special?

They answer "do you have this key, and what is its value?" in **constant time**, regardless of size.
A hash map with ten entries and one with ten million take about the same time to look up.

The mechanism: compute a number from the key (the hash), reduce it to a bucket index, look only in
that bucket. Because it goes straight to one bucket rather than scanning, size does not matter.

Two caveats. If many keys land in the same bucket, that bucket becomes a list and lookup becomes
linear — which is a denial-of-service vector when an attacker chooses the keys. And a hash map has no
order, so "give me the entries in order" needs a different structure.

They matter for Android because the DEX string pool and ART's intern table are exactly this idea,
and understanding one makes the other obvious. ([3.10](README.md#310-data-structures-ii--hash-maps-and-why-they-matter-for-dex))

### 24. Do I need to learn assembly?

You need to **read** it, not write it, and the amount required is much less than people fear.

Concretely: recognise a function's prologue and epilogue; recognise a loop (compare, forward branch
out, backward branch in); recognise a conditional; know where arguments and return values live in the
calling convention; and recognise a call. That is perhaps a day of study and it covers most of what
you will meet.

You will need it whenever the interesting code is in a `.so`, which on Android means whenever a
developer wanted to hide something. ([3.8.6](README.md#386-connecting-to-arm-reversing), [ARM64 in chapter 06](../18-ARM/README.md))

### 25. What is the difference between a stack overflow and a buffer overflow?

Both are writes past a boundary; they differ in what is written past and what that costs.

A **buffer overflow** is writing past the end of any allocation. If the buffer is on the heap it may
corrupt allocator metadata or a neighbouring object; if it is on the stack it may corrupt other
locals or the saved return address.

A **stack overflow** in the exploitation sense is the specific case of overflowing a stack buffer far
enough to overwrite the **saved return address**, so the function returns to an address the attacker
chose. That is the historical route to arbitrary code execution.

Confusingly, "stack overflow" also means the unrelated situation of recursing so deep that the stack
runs out of space — which is a crash, not usually a code-execution bug. Context distinguishes them.
([3.8.3](README.md#383-the-call-stack-drawn), [3.13.3](README.md#3133-the-four-ways-pointers-kill-you))

### 26. Why can't I just zero out a password in Java?

Because `String` is **immutable** by design — there is no method that changes its contents, and every
"modification" creates a new object. So the original bytes stay on the heap until the garbage
collector happens to reclaim them, which may be minutes away or never, and you cannot force it.
String literals are additionally **interned**, meaning they live in a pool for the process lifetime.

The consequence is practical: dump the heap of a running app and you can find passwords that were
"used and discarded" long ago.

The mitigation is `char[]` or `byte[]`, explicitly overwritten in a `finally` block. The better
answer is not to let the secret into the process at all — a Keystore key can be *used* without ever
being *readable*. ([3.14.4](README.md#3144-the-failure-mode-that-matters-most-to-you-secrets-in-the-heap))

### 27. What is the difference between `git reset`, `git revert` and `git checkout`?

They act on different parts of the model, which is why they are confusing until you hold the model.

- **`git checkout` / `git switch`** moves `HEAD` — which commit you are looking at. It changes your
  working files and creates nothing.
- **`git reset`** moves a **branch pointer** to a different commit. `--soft` keeps your files,
  `--hard` overwrites them. Commits left behind still exist, unreferenced.
- **`git revert`** creates a **new commit** that undoes an old one. History is preserved; the change
  is cancelled going forwards.

Rule of thumb: `revert` for anything already pushed (it does not rewrite shared history), `reset` for
local work. And remember `git reflog` — it lists where `HEAD` has been and recovers work you think
you destroyed, because **git almost never actually deletes anything**. ([3.19.2](README.md#3192-the-mental-model-a-dag-of-snapshots))

### 28. If I delete a secret and commit the deletion, is it gone?

**No.** The old commit is still in the repository, reachable by its hash, and it has already been
cloned by everyone who pulled. `git log -S 'secret-value' --all` finds it in seconds, and
`git show <commit>:path` prints it.

The only real remediation is to **rotate the secret** — assume it is compromised, because it is.
Rewriting history with `git filter-repo` is worth doing as well, but it does not un-clone anything and
it invalidates every existing clone, so it is the second step rather than the first.

This is also why the search is a standard engagement step, and why it finds things.
([3.19.4](README.md#3194-the-commands-you-actually-need), [9.5](README.md#95-enterprise--the-same-skills-at-the-scale-of-a-real-review))

### 29. How much of this do I need before starting chapter 04?

You need to be comfortable with: what a variable is in terms of bytes; the difference between stack
and heap; that `int` is 32 bits and wraps; that every `if` is a compare and a branch; what a function
call physically does; what a hash map is for; and the five moves for reading unfamiliar code.

You do **not** need: to have memorised Big-O, to write a hash map from scratch unaided, to read ARM64
fluently, or to have finished all four labs.

Chapter 04 revisits every one of these in Java-specific terms, so partial understanding now becomes
full understanding there. Move on when you can answer the "quick revision" list in
[section 13](README.md#13-summary) without panic. Perfect is the enemy of started.

### 30. I still feel like I do not understand programming. Will that go away?

Partly, and the part that does not go away is normal and shared by everyone doing this work.

What goes away: the feeling that code is arbitrary magic. That is replaced, fairly quickly, by
knowing that everything reduces to moving numbers and branching on comparisons, and that you can
always go down a level and look.

What does not go away: encountering unfamiliar code and having no idea what it does for the first
half hour. That happens to everyone, on every engagement, forever. The difference experience makes is
not that the feeling stops — it is that you acquire a *method* for the half hour, and you stop
interpreting the feeling as evidence that you are not good enough.

That method is [section 8.1](README.md#81-the-single-most-important-pentester-skill-reading-code-you-did-not-write),
and it is the most valuable thing in this chapter.
