# 42 — R8 FAQ

Real questions, including the ones people feel silly asking. Detail in [README.md](README.md).

---

### 1. What actually is R8, in one sentence?

Google's whole-program optimiser and DEX compiler: in a single pass it removes unreachable code, rewrites what remains into a smaller form, renames identifiers, rewrites modern language features for older Android runtimes, and emits DEX.

---

### 2. R8 vs ProGuard — what is the real difference?

Both rename identifiers and both read the same `-keep` rules language, which is why migrating was mostly invisible. The differences that matter to a reverse engineer are **structural**:

| | ProGuard | R8 |
|---|---|---|
| Output format | Java bytecode; `dx` converted it after | DEX directly |
| Knows about DEX limits, `invokedynamic`, `minSdkVersion` | No | Yes |
| Desugaring | Separate tool | Built in |
| Inlining | Conservative | Aggressive, across class boundaries |
| Class merging, enum unboxing, outlining | Limited / none | Yes |
| Mapping file | Flat rename table | Records inline frames, synthetic markers, residual signatures, removed classes |

The one-line version: **ProGuard was a renamer that also deleted things; R8 is a compiler that also renames.** If you keep expecting a renamer, R8's output will keep surprising you.

R8 became the AGP default in **3.4**, and the ProGuard option was removed in **AGP 7.0**. On a modern Android project you are using R8 whether you meant to or not.

---

### 3. Do I still need `-keep` rules with R8?

Yes, and arguably more than with ProGuard, because full mode reads rules **more narrowly**. R8 keeps what it can prove is reachable; anything reached only by name at runtime — reflection, JNI lookups, JSON mappers, service loaders, layout inflation, DI containers — is invisible to it and gets deleted or renamed.

The corollary matters more than the rule: **you cannot tell whether your rules are right by reading them.** Rules also arrive from every AAR's `consumer-rules.pro`, from AGP's generated rules, and from the SDK's default file. Read `build/outputs/mapping/release/configuration.txt` — the merged set — and test the release variant.

---

### 4. Where is `r8.jar`? I cannot find it in the SDK.

There isn't one. R8 and D8 are the same codebase in the same jar, and you pick which compiler you want by choosing a main class:

```bash
java -cp "$ANDROID_HOME/build-tools/35.0.1/lib/d8.jar" com.android.tools.r8.R8 --version
```

Same jar, same build hash, different entry point. This is genuinely useful: any machine with the Android SDK can run R8, `Retrace` and `ExtractMarker` with no Gradle and no project.

---

### 5. What is `$$ExternalSyntheticLambda`?

A class that D8 or R8 generated to hold a desugared lambda or method reference. DEX has no `invokedynamic` below API 26, and the toolchain generally prefers a concrete class anyway, so `myList.sortedBy { it.name }` becomes a real class implementing the functional interface.

The valuable part: the name was **constructed** from the original enclosing class name plus a scheme suffix. `LoginPresenter$$ExternalSyntheticLambda0` tells you a class called `LoginPresenter` existed, even in a build where everything else is `a.b.c`. Every `$$` in a class name works this way — the developer's identifier is to the left of the marker.

---

### 6. What is the difference between `$$ExternalSyntheticLambda` and `$$InternalSyntheticLambda`?

Both are desugared lambdas. `External` is the common form. `Internal` is used when the lambda needs a stable, content-derived identity, and its name contains a **64-hex-character content hash**.

That hash is one of the very few identifiers in an R8 build that is stable across builds, which makes it useful as an anchor when diffing two versions of an app whose ordinary names have all churned.

---

### 7. Why did my app work in debug and crash only in release?

Because debug builds do not run R8. Almost always the cause is a missing keep rule for something reached reflectively, so R8 concluded the code was unreachable and deleted or renamed it. Typical symptoms: `ClassNotFoundException`, `NoSuchMethodException`, a JSON library returning objects with all-null fields, a DI container failing to construct something.

Diagnose with `build/outputs/mapping/release/usage.txt`, which lists everything R8 removed. **Do not fix it by setting `minifyEnabled false`** — that hides the bug, ships a larger unhardened app, and leaves the reflective fragility in place.

---

### 8. Can I get the real names back?

Partially, by several routes, and completely only if the mapping file leaks.

| Route | Gives you |
|---|---|
| A leaked `mapping.txt` | **Everything**, authoritatively |
| Synthetic class names | Original enclosing class names, and sometimes member names |
| `kotlin.Metadata` | Kotlin property names, sometimes class and function names |
| Manifest | Every component class name |
| JNI symbols | Package, class and method name of every native entry point |
| Framework/JDK call targets | Never renamed — the call graph is intact |
| String constants | Never touched |

What you cannot recover without the mapping file: the original names of ordinary internal classes and methods that none of the above touches. Those are genuinely gone; you name them yourself from behaviour.

---

### 9. What is `kotlin.Metadata` and does it really hand back the original names?

It is an annotation `kotlinc` attaches to every class, carrying a protobuf description of the Kotlin declaration, because the JVM class format cannot express Kotlin's type system. Kotlin reflection reads it — which is exactly why you can read it statically.

The common claim is that R8 leaves it alone and it hands back original names wholesale. **Measured, that is too strong.** Four distinct states exist:

| State | What you get |
|---|---|
| **Stripped** — R8's default in both full and compat mode | Nothing |
| **Payload stripped** — annotation present, all elements absent | Nothing, and `grep` gives you a false positive |
| **Rewritten** — `kotlin.Metadata` kept, class renamed | Class and function names are the *obfuscated* ones — **but Kotlin property names survive** |
| **Intact** — the class was never renamed | Everything, though nothing was hidden to begin with |

Across 19 real APKs, ten had no metadata at all and **none** yielded wholesale recovery of an app's own class names. The technique is real, narrow and worth one command; it is not a shovel.

---

### 10. Why do property names survive when function names do not?

Because R8 renames **JVM members**, and a Kotlin property is not one.

A Kotlin function corresponds one-to-one with a JVM method, so when R8 renames the method to `a` it knows the new name and writes it into the metadata's `Function.name`. A Kotlin property is backed by up to three separate JVM members — a field, a getter, a setter — each renamed independently, so there is no single new name to put in `Property.name`. R8 updates the JVM signature extension, which does reference concrete members, and leaves the Kotlin-level name alone.

This also predicts what *is* rewritten: enum entry names and companion object names, because each maps to a JVM field R8 renamed.

---

### 11. Is `grep 'Lkotlin/Metadata;'` enough to test for this?

No. That string lives in the DEX string table and proves only that *something references the type*. One app in the measured corpus had **1,393 classes carrying the annotation with every element absent** — a `grep` reports 1,393 leaks and every one is a false positive.

Parse the structure: `python3 -B scripts/kotlin-metadata-recover.py app.apk --rewrite-check`.

---

### 12. What is R8 full mode and should I be worried about it?

Full mode is R8's more aggressive interpretation of the keep-rules language: `-keep` is read as narrowly as written rather than as generously as ProGuard read it, reflection is assumed absent unless a rule says otherwise, and class merging, enum unboxing and devirtualisation are applied harder. It is the standalone CLI's default and AGP's default from 8.0.

As a developer: yes, mildly — rules that relied on ProGuard's implicit generosity break, and they break only at runtime, in release. Test the release variant.

As an analyst: it means smaller output, more structural rewriting, and a higher ratio of compiler-generated classes to authored ones. Measured on this chapter's sample, full mode produced output **2.6× smaller** than compat mode from identical input.

---

### 13. Why is retracing not just a dictionary lookup?

Because R8 inlines across method and class boundaries, so one runtime frame can represent several source frames. The mapping file encodes this as consecutive entries sharing an obfuscated line range, innermost first. A naive lookup returns the outermost frame and silently drops the rest — which is usually the frame naming the method that actually failed.

In this chapter's sample, a one-frame trace retraced to two frames, and a four-frame trace retraced to twelve.

---

### 14. My release stack trace has one frame. Does that mean it failed early?

No. It means R8 inlined. Frame counts in an R8 release trace describe the optimiser, not the program. Retrace before drawing any structural conclusion.

Relatedly: the line numbers in a release trace are **not source line numbers**. R8 emits a compact synthetic line-number table whose only purpose is to be a lookup key into `mapping.txt`. `SourceFile:16` is not line 16 of anything.

---

### 15. How bad is it if a `mapping.txt` leaks?

Worse than never having obfuscated, and the argument is that **the vendor applied a control and then shipped its key**. Beyond reversing every rename authoritatively, the file discloses:

- every class R8 deleted (`R8$$REMOVED$$CLASS$$n`) — features in the codebase but not this build
- the original source file names, restoring what the DEX flattened away
- the complete inlining record — a partial call graph
- which members are compiler-generated, letting you filter to authored code instantly
- the internal package structure, including packages repackaged flat in the APK
- a hash (`pg_map_hash`) and id (`pg_map_id`) tying it to one exact build

Default severity **Medium**, moving with what the recovered code protects. Run `mapping-reader.py <file> stats` and put that output in the report — it makes the structural disclosure concrete rather than theoretical.

---

### 16. I found `proguard.map` inside an `.aab`. Is that a finding?

**No.** `BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map` is where the mapping is *supposed* to live in an App Bundle, so Play can symbolicate crashes. It never reaches a device. Reporting it is reporting the format working as designed.

The finding is a mapping inside an *installed APK*, or on a publicly reachable URL.

---

### 17. Can I prove a mapping file belongs to a particular APK?

Yes, and you should before trusting a single name from it. R8 writes a `pg_map_id` header into the mapping and can embed the same id as a marker in the DEX:

```bash
java -cp "$ANDROID_HOME/build-tools/35.0.1/lib/d8.jar" com.android.tools.r8.ExtractMarker app.apk
python3 -B scripts/mapping-reader.py mapping.txt stats     # prints pg_map_id
```

If they match, the pairing is established. If they do not, you are about to produce confident wrong answers — R8's name assignment changes between builds, so a mismatched mapping still "works" and still resolves `a.b.c` to *something*.

---

### 18. Is "the app is not obfuscated" a vulnerability?

No. It is a **missing hardening control**, and obfuscation was never a security boundary. Reported as high severity it damages your report's credibility, because a competent developer will point out that `minifyEnabled true` fixes nothing that was actually broken.

Report it as informational or low, with severity driven by what it exposes. And if obfuscation was the only thing protecting a secret, **report the secret** — "hardcoded API key with no server-side control" — and cite the obfuscation as context. Writing it the other way round invites an argument about obfuscation instead of a key rotation.

---

### 19. Should we enable obfuscation at all, then?

Yes — it is nearly free, it is a recognised MASVS-RESILIENCE control, it raises the cost of casual and automated analysis, and its byproducts (shrinking and optimisation) are independently valuable.

But require it while explicitly denying it a role in the threat model. The failure to design against is not "obfuscation was absent"; it is **"obfuscation was counted on"** — a team leaving a secret client-side because the code is hard to read.

If you need more than R8 gives you, the layers that matter are the ones R8 does not provide: string encryption and control-flow obfuscation. R8 leaves strings and the framework call graph completely intact, and those are what an analyst navigates by.

---

### 20. R8 fails with "Unsupported class file major version 68" — is that a bug?

No, and the message is misleading because R8 reports it as *"Compilation failed with an internal error"*. R8 8.6.x cannot read class files newer than **Java 21** (major 65). If your default JDK is 22 or newer, run R8 under an older one — Android Studio ships a JDK 21 at `<studio>/jbr`:

```bash
"/c/Program Files/Android/Android Studio/jbr/bin/java.exe" -cp "$D8" com.android.tools.r8.R8 ...
```

---

### 21. Why do the obfuscated names change every time I build?

Because R8 allocates names globally across the whole optimised program, so any change anywhere can shift the assignment. Adding one unused class can rename half the app.

Three consequences: a mapping file is version-specific; a Frida script hooking `a.b.c` breaks on the next release **silently**, because `a.b.c` usually still exists on something else; and diffing two versions on names alone is pure noise. Hook and diff on structure, constants and framework call targets. Developers who need stability use `-applymapping`.

---

### 22. How do I tell how obfuscated an app really is?

Measure the **application's own package**, not the whole APK — dependencies are obfuscated regardless of what the app exempts for itself, so a whole-APK average will call an app "well obfuscated" when it exempted every one of its own classes.

Count classes whose simple name is three characters or fewer. Above 80% means it is working; below 20% *with* an `~R8` marker means keep rules neutered the renaming, which is the actual finding. Defend the heuristic with two cross-checks: the length distribution should be bimodal with a spike at 1–2 characters, and simple names should be reused across many packages. Real codebases show neither.

---

### 23. Should I report the original names leaking through synthetic class names?

No. That is a fact about how compilers work, not a vendor mistake, and there is no remediation a developer could apply. Use it during analysis; leave it out of the findings.

The related thing that *is* worth a sentence is the pattern of keep rules: if the classes that kept their names are the reflective entry points,keep-rule review is warranted, at informational severity.
