# Kotlin — References

Sources used for chapter [05 — Kotlin](../README.md), grouped by purpose. Every entry has a one-line
note explaining what it is good for. Where a resource is best known by name rather than by a stable URL,
it is named rather than linked, so nothing here is invented.

---

## 1. Official Kotlin language documentation

- [Kotlin Documentation home](https://kotlinlang.org/docs/home.html) — the entry point to every official topic page; start here when a construct is unfamiliar.
- [Kotlin language specification](https://kotlinlang.org/spec/) — the normative document defining semantics; the only place that settles arguments about corner cases.
- [Basic syntax](https://kotlinlang.org/docs/basic-syntax.html) — the fastest orientation for a reader arriving from Java.
- [Null safety](https://kotlinlang.org/docs/null-safety.html) — nullable types, safe calls, the Elvis operator, the not-null assertion, and platform types.
- [Type checks and casts](https://kotlinlang.org/docs/typecasts.html) — `is`, `as`, `as?`, and smart casts, which explain many odd-looking decompiled branches.
- [Classes and inheritance](https://kotlinlang.org/docs/classes.html) — primary constructors, `init` blocks, and the final-by-default rule.
- [Data classes](https://kotlinlang.org/docs/data-classes.html) — states exactly which members the compiler generates, which is the contract you rely on when reading JADX.
- [Sealed classes and interfaces](https://kotlinlang.org/docs/sealed-classes.html) — the restricted hierarchy rules that produce `DefaultConstructorMarker` constructors.
- [Object declarations and expressions](https://kotlinlang.org/docs/object-declarations.html) — the source of the `INSTANCE` field and the `Companion` nested class.
- [Extensions](https://kotlinlang.org/docs/extensions.html) — explains static dispatch and why extensions are not members.
- [Functions](https://kotlinlang.org/docs/functions.html) — default arguments, named arguments, varargs, and infix functions.
- [Higher-order functions and lambdas](https://kotlinlang.org/docs/lambdas.html) — function types, `it`, closures, and receivers.
- [Inline functions](https://kotlinlang.org/docs/inline-functions.html) — inlining, `noinline`, `crossinline`, `reified`, and non-local returns.
- [Scope functions](https://kotlinlang.org/docs/scope-functions.html) — the official selection table for `let`, `run`, `with`, `apply`, and `also`.
- [Delegated properties](https://kotlinlang.org/docs/delegated-properties.html) — `by lazy`, `Delegates.observable`, and the `getValue`/`setValue` contract.
- [Delegation](https://kotlinlang.org/docs/delegation.html) — interface delegation with `by`, which produces the `$$delegate_0` field.
- [Generics](https://kotlinlang.org/docs/generics.html) — declaration-site variance with `in` and `out`, star projections, and type erasure.
- [Collections overview](https://kotlinlang.org/docs/collections-overview.html) — the read-only versus mutable distinction and why it is compile-time only.
- [Sequences](https://kotlinlang.org/docs/sequences.html) — lazy evaluation and when it beats eager collection operators.
- [Coding conventions](https://kotlinlang.org/docs/coding-conventions.html) — the naming rules that let you guess a symbol's role from its shape.
- The per-version "What's new in Kotlin" pages on `kotlinlang.org/docs` — useful for dating an APK's compiler generation from which helper names it emits, for example `checkParameterIsNotNull` before Kotlin 1.4 versus `checkNotNullParameter` after it.

## 2. Coroutines and concurrency

- [Coroutines guide](https://kotlinlang.org/docs/coroutines-guide.html) — the official tutorial series covering builders, context, channels, and flows.
- [Coroutines basics](https://kotlinlang.org/docs/coroutines-basics.html) — suspending functions, scope, and the first mental model.
- [Composing suspending functions](https://kotlinlang.org/docs/composing-suspending-functions.html) — sequential versus concurrent composition with `async`.
- [Coroutine context and dispatchers](https://kotlinlang.org/docs/coroutine-context-and-dispatchers.html) — the definitive description of `Dispatchers.Main`, `Default`, `IO`, and `Unconfined`.
- [Cancellation and timeouts](https://kotlinlang.org/docs/cancellation-and-timeouts.html) — why cancellation is cooperative and what `CancellationException` means.
- [Asynchronous flow](https://kotlinlang.org/docs/flow.html) — cold streams, operators, `flowOn`, and back-pressure.
- [Exception handling](https://kotlinlang.org/docs/exception-handling.html) — how failures propagate through a scope hierarchy and what `SupervisorJob` changes.
- [kotlinx.coroutines on GitHub](https://github.com/Kotlin/kotlinx.coroutines) — the library implementation; read `BaseContinuationImpl` and `DispatchedTask` to see the machinery your Frida hooks attach to.
- [kotlinx.coroutines API reference](https://kotlinlang.org/api/kotlinx.coroutines/) — signatures for every builder, dispatcher, and flow operator.
- [Kotlin Evolution and Enhancement Process (KEEP) repository](https://github.com/Kotlin/KEEP) — the design documents behind every language feature, including the rationale nobody puts in the user docs.
- [KEEP: coroutines design document](https://github.com/Kotlin/KEEP/blob/master/proposals/coroutines.md) — the single most valuable document for understanding Continuation Passing Style, the `COROUTINE_SUSPENDED` sentinel, and the state-machine transformation.

## 3. Java interoperability and the JVM back end

- [Calling Java from Kotlin](https://kotlinlang.org/docs/java-interop.html) — platform types, SAM conversion, and mapped types.
- [Calling Kotlin from Java](https://kotlinlang.org/docs/java-to-kotlin-interop.html) — the authoritative description of `@JvmStatic`, `@JvmField`, `@JvmName`, `@JvmOverloads`, and companion-object visibility from Java.
- [Kotlin and Java mixed-language projects](https://kotlinlang.org/docs/mixing-java-kotlin-intellij.html) — how the two compilers cooperate in one module.
- [Android Kotlin-Java interop guide](https://developer.android.com/kotlin/interop) — Google's rules for writing API surfaces that stay pleasant from both languages.
- The `kotlin-metadata-jvm` library, in the `JetBrains/kotlin` repository under `libraries/` — the official parser for the `@Metadata` annotation; the correct way to read Kotlin declaration information out of a class file programmatically.

## 4. Android-specific Kotlin

- [Android developers: Kotlin](https://developer.android.com/kotlin) — the hub page for Kotlin on Android.
- [Kotlin coroutines on Android](https://developer.android.com/kotlin/coroutines) — `lifecycleScope`, `viewModelScope`, and the main-safety pattern.
- [Improve app performance with Kotlin coroutines](https://developer.android.com/kotlin/coroutines/coroutines-adv) — cancellation, exceptions, and the `withContext` guidance most apps follow.
- [Kotlin flows on Android](https://developer.android.com/kotlin/flow) — `StateFlow`, `SharedFlow`, and lifecycle-aware collection.
- [Android Kotlin style guide](https://developer.android.com/kotlin/style-guide) — the conventions that determine what generated names look like in a typical app.
- [Jetpack Compose documentation](https://developer.android.com/jetpack/compose) — a Kotlin-only toolkit whose compiler plugin adds yet another layer of generated code you will meet in decompiled UIs.
- [Kotlin Multiplatform documentation](https://kotlinlang.org/docs/multiplatform.html) — `expect`/`actual`, shared source sets, and how shared code still becomes ordinary DEX on Android.

## 5. Compiler, bytecode, and toolchain

- [JetBrains/kotlin on GitHub](https://github.com/JetBrains/kotlin) — the compiler itself; the JVM back end is where every generated member described in this chapter is actually produced.
- [Dalvik Executable format](https://source.android.com/docs/core/runtime/dex-format) — the DEX header, string identifier table, and type descriptors that `scripts/detect-kotlin.py` parses.
- [Android: shrink, obfuscate, and optimize your app](https://developer.android.com/build/shrink-code) — how R8 treats Kotlin, including which `Intrinsics` calls it can remove.
- [R8 source repository](https://r8.googlesource.com/r8) — the shrinker and DEX compiler used by every modern Android build.
- [JADX](https://github.com/skylot/jadx) — the decompiler assumed throughout this chapter, including its Kotlin metadata support and `--deobf` renaming.
- [Apktool](https://apktool.org/) — resource decoding and smali round-tripping.
- [smali and baksmali](https://github.com/google/smali) — the assembler and disassembler for the DEX format.
- [Frida documentation](https://frida.re/docs/home/) — the instrumentation framework used in the labs.
- [Frida JavaScript API reference](https://frida.re/docs/javascript-api/) — `Java.perform`, `Java.use`, `Java.choose`, and overload resolution.

## 6. OWASP MASVS and MASTG

The OWASP Mobile Application Security project is the assessment framework this repository maps to.
Kotlin-specific findings almost always land in one of the control groups below; consult the MASTG site
for the current test identifiers, which are renumbered periodically.

- [OWASP Mobile Application Security home](https://mas.owasp.org/) — the umbrella project.
- [OWASP MASVS](https://mas.owasp.org/MASVS/) — the verification standard; the control groups are `MASVS-STORAGE`, `MASVS-CRYPTO`, `MASVS-AUTH`, `MASVS-NETWORK`, `MASVS-PLATFORM`, `MASVS-CODE`, `MASVS-RESILIENCE`, and `MASVS-PRIVACY`.
- [OWASP MASTG](https://mas.owasp.org/MASTG/) — the testing guide with concrete procedures and current test identifiers.

| Kotlin-specific issue from this chapter | MASVS control group | What to verify |
|---|---|---|
| Data-class `toString` writing tokens to logcat | `MASVS-STORAGE` | No sensitive data reaches system logs or crash reports |
| Secrets held in `by lazy` delegates or `companion object` constants | `MASVS-CRYPTO`, `MASVS-STORAGE` | Keys are not hardcoded and are not recoverable from the DEX or from memory |
| `!!` on `Intent` extras in exported components | `MASVS-PLATFORM` | IPC input is validated before use; components are not crashable by third-party apps |
| Platform types from Java or JNI used as non-null | `MASVS-CODE` | External input is validated at the boundary |
| Suspend functions performing network work without pinning or validation | `MASVS-NETWORK` | Transport security is enforced regardless of which dispatcher the call runs on |
| `Intrinsics` strings and `@Metadata` leaking original names in a release build | `MASVS-RESILIENCE` | Obfuscation configuration matches the app's threat model |
| Personal data flowing through flows and continuations into logs | `MASVS-PRIVACY` | Data minimisation and no incidental persistence |

## 7. Books

- *Kotlin in Action*, Dmitry Jemerov and Svetlana Isakova, Manning — the standard book for Java developers; chapters on lambdas, inline functions, and Java interop are directly relevant to reading decompiled output. A second edition co-authored with Roman Elizarov and Sebastian Aigner adds coroutines and flows.
- *Atomic Kotlin*, Bruce Eckel and Svetlana Isakova — small self-contained lessons, well suited to a reader who has never programmed before.
- *Effective Kotlin*, Marcin Moskała — idioms and their costs; useful for predicting what a well-written codebase looks like and therefore what an anomaly looks like.
- *Kotlin Coroutines: Deep Dive*, Marcin Moskała — the most thorough treatment of the continuation and state-machine transformation outside the KEEP document.
- *Android Security Internals*, Nikolay Elenkov, No Starch Press — the platform-security background this repository assumes; predates Kotlin but the runtime and IPC material is unchanged.
- *The Mobile Application Hacker's Handbook*, Chell, Erasmus, Colley, and Whitehouse, Wiley — assessment methodology to hang the Kotlin-specific techniques on.

## 8. Talks and long-form articles

Conference-talk URLs move between hosting platforms, so these are named rather than linked; each is
findable by title on the KotlinConf and JetBrains channels.

- Roman Elizarov, *Deep Dive into Coroutines on JVM* (KotlinConf) — the talk that walks through the compiler's state-machine transformation with real bytecode; the closest thing to a video version of this chapter's coroutine section.
- Roman Elizarov, *Structured Concurrency* (article series) — the argument for scoping every coroutine, and the reasoning behind `coroutineScope` and `supervisorScope`.
- Roman Elizarov, *Blocking Threads, Suspending Coroutines* (article) — the clearest short explanation of why a suspended coroutine occupies no thread.
- Andrey Breslav and later JetBrains language-design talks on *Why Kotlin looks the way it does* — the pragmatic trade-offs behind platform types and interop.
- Jake Wharton's talks on Kotlin's generated code and on multiplatform — consistently focused on what the compiler actually emits rather than on syntax.
- The *Talking Kotlin* podcast, JetBrains — episodes with the compiler team cover back-end decisions that never appear in user documentation.

## 9. Chapters in this repository that build on this one

- [04 — Java](../../04-Java/README.md) — the language the decompiler outputs; prerequisite for everything here.
- [10 — APK Internals](../../10-APK-Internals/README.md) — where `classes.dex` lives and how to extract it.
- [12 — DEX Internals](../../12-DEX-Internals/README.md) — the string table format that `detect-kotlin.py` walks.
- [13 — ART](../../13-ART/README.md) — how these methods are actually executed and compiled.
- [26 — Intent](../../26-Intent/README.md) — the delivery mechanism for the null-safety crash cases described in the FAQ.
