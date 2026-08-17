# 41 — ProGuard — FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct; the reasoning
is in [README.md](README.md).

Measurements cited here were taken on Android SDK build-tools 35.0.1 with **R8 8.6.2-dev**, JDK 24,
and a physical `i9000S` (Android 13 / API 33, not rooted). Re-measure on your own toolchain before
repeating any of them as fact.

---

### 1. Is ProGuard still used on Android? Should I learn it?

Not as an engine, yes as a language.

**R8** has been the default shrinker since Android Gradle Plugin 3.4 (2019), and AGP 7.0 removed the
option to select ProGuard at all. There is no ProGuard binary in the Android SDK. When you set
`minifyEnabled true`, R8 runs.

But the file is still called `proguard-rules.pro`, the language inside it is still ProGuard's, every
library ships rules in it, and R8 was built as a drop-in replacement precisely so those rules would
keep working. You will also meet real ProGuard output in pre-2019 apps, in non-Android Java, and in
apps protected by **DexGuard**, which is ProGuard's commercial descendant and speaks a superset of
the same language.

So: learn the **rules language**. That is what this chapter is.

---

### 2. Will enabling obfuscation break my app?

Probably, the first time, and always in the same category: **something that is resolved by name at
runtime.** The shrinker reasons about bytecode references. It cannot see a name that only exists as
a string.

The usual culprits, and what each looks like when it breaks:

| Mechanism | Symptom |
|---|---|
| `Class.forName("…")` | `ClassNotFoundException` |
| `getMethod` / `getDeclaredField` | `NoSuchMethodException` / `NoSuchFieldException` |
| `Enum.valueOf("REFUND")` | `IllegalArgumentException: No enum constant` |
| GSON without `@SerializedName` | JSON keys silently become `a`, `b`, `c` |
| GSON with generics, `Signature` dropped | you get a `LinkedTreeMap` instead of your model |
| Statically bound JNI | `UnsatisfiedLinkError` naming a symbol that is not in the `.so` |
| Java serialisation | old data will not deserialise after an update |
| A class named in a layout XML | inflation fails at runtime |

The fix is never `-dontobfuscate`. It is a rule naming the specific thing that is looked up.

The failure mode that hurts is that these are *runtime* failures on paths nobody exercised in
testing. Budget a full regression pass, not a smoke test.

---

### 3. Why is one of my classes still named clearly when everything else is `a`?

Six causes, in the order they are usually the right one:

1. **It is a manifest component.** AGP generates a keep for every `<activity>`, `<service>`,
   `<receiver>`, `<provider>` and `<application>`, plus every custom `View` named in a layout. You
   did not write that rule and you cannot delete it — nor should you, because `PackageManager`
   starts components by that exact string.
2. **A dependency's consumer rules keep it.** Invisible from your own file. Read
   `app/build/outputs/mapping/<variant>/configuration.txt`.
3. **It has a `native` method.** The standard JNI rule keeps the name of any class that declares
   one.
4. **A `-keep` in your file matches more than you thought.** Usually a `**`.
5. **It is a reflection or serialisation target** and somebody kept it deliberately.
6. **It is an artefact.** A class kept by `-keepclasseswithmembernames` whose triggering member was
   later shrunk away — measured in this chapter's fixture, where `LicenseValidator` keeps its
   original name and has an **empty body**.

To find out which, run `-whyareyoukeeping` on it, or use this chapter's tools:

```bash
# host
python3 -B scripts/what-survived.py app.apk --rules app/proguard-rules.pro
```

Section 5 of that report lists survivors your rules do **not** explain, which is where causes 1–3
show up.

---

### 4. What is `-keepattributes` for?

Class-file attributes are metadata attached to classes, fields and methods. Shrinkers throw all of
them away by default. `-keepattributes` names the ones to keep.

The four that matter in practice:

| Attribute | Keep it when |
|---|---|
| `Signature` | anything reflects over generics — GSON's `TypeToken` is the classic. Without it, `List<User>` becomes a raw `List` and deserialisation returns `LinkedTreeMap` |
| `RuntimeVisibleAnnotations` (+ `…ParameterAnnotations`) | you use Retrofit, Room, GSON's `@SerializedName`, or any DI framework. The annotation values are read at runtime |
| `SourceFile` + `LineNumberTable` | you want stack traces that a mapping file can turn back into source locations |
| `InnerClasses` + `EnclosingMethod` | `getSimpleName()` or anything that walks nested types |

Never keep `LocalVariableTable` or `LocalVariableTypeTable` in a release build — they carry the
developer's own local variable names, and decompiled output with them reads almost like source.

`-keepattributes *` keeps everything including those. Name what you need.

---

### 5. Does this protect my API key?

**No. Not at any setting, not with any rule.**

Renaming does not touch string constants. There is no directive in ProGuard or R8 that removes,
alters or encrypts one — the program needs those exact bytes, so they are in the DEX string pool in
plain text before and after minification. `strings classes.dex | grep -i key` finds it either way.

This chapter's fixture demonstrates it in the least ambiguous way possible: the "public key"
constant and the telemetry URL are byte-identical in the unminified build, the tightly-minified
build and the over-broadly-minified build. The tightened build renamed the class, renamed the field
and deleted a third of the program. The strings are untouched.

The only correct answers to "how do I protect this secret in my app" are:

- Do not put it in the app. Move the operation behind an authenticated server call.
- If it must be present, scope it so that possession is not sufficient — bind it to a device, an
  attested session, or a short-lived token.

String **encryption** is a different technique from a different class of tool, and it delays rather
than prevents. See [40-Obfuscation §3.2](../40-Obfuscation/README.md).

---

### 6. What is the difference between `*` and `**`? I keep getting this wrong.

`*` matches any sequence of characters **except** the package separator `.`.
`**` matches any sequence **including** `.`.

| Pattern | Matches |
|---|---|
| `com.app.*` | classes directly in `com.app` |
| `com.app.**` | `com.app` **and every package beneath it** |
| `*Activity` | classes in the **default package** ending in `Activity` — almost certainly nothing |
| `**Activity` | any class anywhere ending in `Activity` |

And the one that catches everybody, which is documented behaviour rather than a bug: **the class
name `*` on its own matches every class, irrespective of package.** So `-keep class *` keeps the
entire program, even though `*` does not otherwise cross `.`.

There is also `***`, which is a **type** wildcard, not a name wildcard: it appears in return types,
field types and argument types, and unlike `*` it matches arrays. `%` matches primitives only, and
`(...)` matches any argument list.

---

### 7. What does `-keep class com.myapp.** { *; }` actually cost me?

Three things, and most people only know about the first.

1. **Nothing in your namespace is renamed.**
2. **Nothing in your namespace is shrunk.** Every dead class, every abandoned helper, every leftover
   constant ships to production. In this chapter's fixture, that rule put a class called `DeadCode`
   and its constant `staging-token-do-not-ship` back into the APK; the tightened build removed both.
3. **Nothing in your namespace is optimised.** No inlining, no class merging, no dead-branch
   elimination inside kept members.

Measured: the same fixture built with tightened rules produced a 2,920-byte `classes.dex` with 4
classes; built with that one wildcard rule it produced 7,180 bytes and 12 classes — within 3% of the
build that had minification switched **off**.

If you are going to keep the rule, at least know that you are shipping dead code, and audit what is
in it.

---

### 8. My crash reports are unreadable. Can I just add `-dontobfuscate`?

You can, and you should not.

The correct fix is two lines and it costs you nothing:

```proguard
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
```

The first keeps what a stack trace needs. The second overwrites every `SourceFile` value with one
constant, so line numbers still resolve but your original filenames do not ship. Then upload
`mapping.txt` to your crash service, or retrace locally:

```bash
# host
BT=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
java -cp "$BT/lib/d8.jar" com.android.tools.r8.retrace.Retrace mapping.txt trace.txt
```

`-dontobfuscate` gives up the whole control to fix a tooling problem that has a two-line answer, and
once it is in the file nobody remembers why, so it never comes out.

---

### 9. Where is `mapping.txt`, and what happens if it leaks?

`app/build/outputs/mapping/<variant>/mapping.txt`, alongside `seeds.txt`, `usage.txt` and
`configuration.txt`.

If it leaks, the app's obfuscation is completely reversed in one command:

```bash
# host
jadx -Prename-mappings.format=PROGUARD_FILE --mappings-path mapping.txt -d out app.apk
```

It leaks in five places, in the order worth checking: inside the APK (someone put it in `assets/`
for a crash SDK); committed to the repository, including in history after a "fix" commit; attached
to a public release or CI artefact; on the crash-reporting service, where it is *supposed* to be but
where the account may be over-permissive; and in an internal artefact repository that turns out to
be world-readable.

Check the APK first, because it is the cheapest and the most damning:

```bash
# host
unzip -l app.apk | grep -iE 'mapping\.txt|seeds\.txt|usage\.txt|configuration\.txt|\.pro$'
```

Severity is **proportional to what the obfuscation was protecting**. For a payments or DRM app it is
serious. For an app that enabled minification because the template did, it is informational.

---

### 10. Is "the app is not obfuscated" a finding?

By itself, no. It is a **hardening observation**, and reporting it as a medium or high severity
finding is one of the more reliable ways to lose a development team's attention.

Say the threat model first. MASVS-RESILIENCE is explicitly a defence-in-depth category that applies
to apps whose threat model includes a hostile user — payments, DRM, licensing, anti-fraud, games with
a client-side economy, enterprise agents. If the app is not in that group, the honest write-up is one
informational paragraph.

Two things make it a finding worth writing:

- **An over-broad `-keep` that defeats a control the team clearly intended.** That is specific, it is
  evidence of intent, and the fix is cheap.
- **Retained dead code that contains something.** Non-public endpoints, staging constants,
  credentials. That is a separate finding at its own severity, and it is usually the more valuable
  one.

And never accept obfuscation as remediation for a real defect. If the answer to a hardcoded
credential is "we will obfuscate it", extract it from the obfuscated build in front of them.

---

### 11. Why did my app get bigger / not get smaller after enabling minification?

Three common causes.

1. **You are comparing APK sizes on a small app.** `apksigner` pads the APK Signing Block so the ZIP
   central directory begins on a 4096-byte boundary. All three builds of this chapter's fixture came
   out at *exactly* 12,757 bytes while their `classes.dex` files differed by more than 2×. Compare
   `classes.dex`, not the APK.
2. **An over-broad keep is preventing shrinking.** See question 7.
3. **You used `proguard-android.txt` instead of `proguard-android-optimize.txt`.** The non-`optimize`
   default file contains `-dontoptimize`.

---

### 12. What is `seeds.txt` and why should I care?

It lists **every class and member that a keep rule matched** — the root set. It is the single best
artefact for auditing your own rules, and it is more directly useful than `mapping.txt` for that
purpose.

Two uses:

- **As a developer:** if the seed count is close to your total class count, a rule is matching
  everything. Track it over time; a jump means a rule widened, possibly in a dependency.
- **As an analyst, if you ever obtain one:** it is a list of everything the developers believed was
  accessed by name at runtime. That is a map of the app's reflection, serialisation and native
  boundaries — a statement of intent rather than a mechanical record.

```bash
# host — the package distribution of the seeds, where the surprise usually is
cut -d: -f1 app/build/outputs/mapping/release/seeds.txt \
  | sed 's/\.[A-Z][A-Za-z0-9_$]*$//' | sort | uniq -c | sort -rn | head -20
```

---

### 13. A library's rules are keeping half my app. Can I remove them?

**No.** Keep rules are purely additive; there is no "unkeep" directive in the language.

A library ships `consumerProguardFiles` content as `proguard.txt` inside its AAR (or
`META-INF/proguard/*.pro` inside a JAR), and AGP merges it into your build. From inside your project
the imposition is invisible — it is not in your file.

Your options are: remove the dependency; fork or repackage the AAR with corrected rules; shade the
library into your own namespace so the rule no longer matches; or raise it with the maintainer.

Find them first:

```bash
# host
less app/build/outputs/mapping/release/configuration.txt   # merged, with origin comments

find ~/.gradle/caches/modules-2 -name '*.aar' | while read -r a; do
    unzip -l "$a" 2>/dev/null | grep -q proguard.txt && { echo "== $a"; unzip -p "$a" proguard.txt; }
done
```

---

### 14. I audited `proguard-rules.pro` and it looked fine. Am I done?

No. Your file is typically a small fraction of the configuration. R8 also receives:

1. the SDK defaults from `getDefaultProguardFile(...)`,
2. AGP's generated manifest and layout keeps
   (`app/build/intermediates/aapt_proguard_file/<variant>/aapt_rules.txt`),
3. every dependency's consumer rules,
4. R8's own built-in assumptions.

Audit the merged record instead:

```bash
# host
python3 -B scripts/proguard-rules-audit.py \
    app/build/outputs/mapping/release/configuration.txt --min-severity MEDIUM
```

Expect it to be one to two orders of magnitude larger than your own file.

---

### 15. `what-survived.py` says 0% of my classes were renamed, but I can see they were. What?

You almost certainly used `--package`.

**Renaming rewrites the package as well as the class.** `com.pentest.ch41.Transaction` became `a.a`
— it is no longer under `com.pentest.ch41` at all, so a package filter removes it from the census and
what remains is exactly the set of classes that *kept* their names. The result reads 0% renamed,
which is the opposite of the truth.

The tool prints a warning above the verdict when this happens, and so does
`scripts/frida-keep-census.js`. Run it both ways and compare. This is a genuinely easy mistake to
make in the reassuring direction, which is why both tools call it out.

---

### 16. Does R8 understand reflection now? Can I delete my keep rules?

**Partly, and no.**

Measured on R8 8.6.2: delete the `Class.forName` keep from this chapter's fixture, rebuild, and the
app still works. R8 recognises the constant-string `Class.forName` idiom, resolves it at build time,
replaces the call with a `const-class` instruction, keeps the class, renames it, and rewrites the
reference. The string is not even in the DEX any more.

Now the counter-example, from the same session and the same toolchain. In
[`labs/ctf-vault`](labs/ctf-vault/), R8 resolved `Class.forName("…Piece5")` in exactly the same way —
**and then removed `Piece5`'s `public static final String FIFTH` anyway**, reducing the class to an
empty `abstract` shell, because `getDeclaredField(String)` is not modelled. The build printed no
warning. The app throws `NoSuchFieldException` at runtime, on a path nobody tested.

The modelling is **idiom matching, not analysis**. It stops abruptly and silently, and you cannot
tell from reading your source which side of the boundary you are on. So: write the keep. A redundant
rule costs nothing; a missing one costs a production crash.

---

### 17. What is `-if` for?

It makes the *next* keep rule conditional on another class specification matching, and it can
back-reference the condition's wildcards:

```proguard
-if class com.example.ui.**
-keep class <1>Presenter {
    <init>(...);
}
```

`<1>` expands to whatever `**` matched. Libraries use it to say "keep the generated companion of
anything of mine that you actually use" without keeping the whole package. Retrofit, Room and Dagger
consumer rules all use this shape.

If you are about to write a package wildcard, ask first whether the requirement is really
conditional. `-if` is the tool for narrowing exactly that instinct.

---

### 18. What does `-assumenosideeffects` do, and why do people warn about it?

It tells the optimiser that calls to the named methods may be deleted. The canonical use is
stripping verbose logging:

```proguard
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}
```

The optimiser then removes the calls *and the expressions that computed their arguments*, which is
the point — `Log.d(TAG, expensiveDump())` deletes the `expensiveDump()` call too.

Three ways it goes wrong:

1. **It applies to return values.** R8 will happily replace a call it believes is side-effect-free
   with a constant. Assume a method that returns something meaningful and you may delete the branch
   that depended on it — including a security check.
2. **`Log.w` and `Log.e` are excluded on purpose.** A rules file that includes them has silently
   deleted its own error logging.
3. **The argument expressions go too**, which is desirable right up until one of them had a side
   effect.

`-assumevalues` is stronger still. Treat both as code, not configuration.

---

### 19. Should I use `@Keep` instead of writing rules?

`androidx.annotation.Keep` is fine and often clearer, but understand what it is: **ordinary
configuration, not a compiler feature.** It works because AGP's default rules file contains
something equivalent to:

```proguard
-keep @androidx.annotation.Keep class * { *; }
-keepclassmembers class * { @androidx.annotation.Keep *; }
```

Two consequences. First, `@Keep` on a class typically keeps *all* its members — a blunt instrument
applied at a fine granularity, which is usually a reasonable trade. Second, if the annotation is
stripped (the retention attribute was dropped, or the annotation class itself was shrunk away), the
rule matches nothing and `@Keep` silently stops working.

Use it for things whose keep requirement belongs next to the code. Use rules for things that belong
in one reviewable place — and comment both.

---

### 20. Where do I even start on an obfuscated app?

Not with the code. In this order:

1. **The manifest.** Never obfuscated. Every component names a class that must exist under that exact
   name. Those are your entry points.
2. **The resources.** `layout/activity_pin`, `id/pin_entry`, `string/login_failed`. R8 does not touch
   `resources.arsc` at any setting.
3. **The strings.** URLs, JSON keys, SQL, error messages, log tags. Renaming never touched one of
   them. On a real 22.8 MB app measured for this chapter, the sweep returned 68 distinct URLs and
   42,451 long strings in an app that was half renamed.
4. **The native libraries.** `strings *.so | grep '^Java_'` gives you post-rename Java class names in
   the clear, and they name the classes important enough to have native code behind them.
5. **The annotations.** If `RuntimeVisibleAnnotations` survived, `grep -rhoE '@(GET|POST)\("[^"]+"\)'`
   on a jadx dump reconstructs the API surface.
6. **Then** the code, renaming things yourself as you understand them, and persisting the renames.

[56-JADX](../56-JADX/README.md) owns step 6. [40-Obfuscation](../40-Obfuscation/README.md) owns the
methodology as a whole.
