# 41 — ProGuard / R8 rules cheat sheet

Dense reference. Prose lives in [README.md](README.md).
Engine assumed: **R8** (the AGP default since 3.4). ProGuard-only behaviour is marked **[PG]**.

---

## 1. The keep matrix

|  | Keeps the class | Keeps only members | Keeps class **if it has** the members |
|---|---|---|---|
| **Removal + renaming** | `-keep` | `-keepclassmembers` | `-keepclasseswithmembers` |
| **Renaming only** (`allowshrinking`) | `-keepnames` | `-keepclassmembernames` | `-keepclasseswithmembernames` |

| Directive | Class kept | Class name kept | Members kept | Member names kept | Condition |
|---|---|---|---|---|---|
| `-keep` | ✅ | ✅ | ✅ | ✅ | class matches |
| `-keepclassmembers` | ❌ | ❌ | ✅ | ✅ | class matches |
| `-keepclasseswithmembers` | ✅ | ✅ | ✅ | ✅ | class matches **and has all named members** |
| `-keepnames` | ❌ | ✅ | ❌ | ❌ | class matches |
| `-keepclassmembernames` | ❌ | ❌ | ❌ | ✅ | class matches |
| `-keepclasseswithmembernames` | ❌ | ✅ | ❌ | ✅ | class matches **and has all named members** |

**Two-question decoder.** Contains `names` → cannot stop deletion. Contains `classmembers` → does not
protect the class.

---

## 2. Keep modifiers

Appended with commas, no space: `-keep,allowobfuscation class …`

| Modifier | Effect |
|---|---|
| `allowshrinking` | may still be removed; only the name is protected |
| `allowobfuscation` | may still be renamed; only presence is protected |
| `allowoptimization` | may still be inlined / merged / reshaped |
| `allowaccessmodification` | access modifiers may be widened |
| `includedescriptorclasses` | classes in the kept members' **signatures** are kept and unrenamed too |
| `includecode` | the matched methods' bytecode is preserved unchanged |

---

## 3. Wildcards

| Token | Legal in | Matches | Crosses `.` |
|---|---|---|---|
| `?` | class + member names | exactly one character | no |
| `*` | class + member names | any sequence | **no** |
| `**` | class names | any sequence | **yes** |
| `***` | **type positions only** | any type, incl. primitives and arrays | n/a |
| `%` | type positions only | any **primitive** (not `void`, not objects) | n/a |
| `...` | argument lists only | any number of arguments of any type | n/a |
| `<init>` | member names | any constructor | |
| `<clinit>` | member names | the static initialiser | |
| `<fields>` | member spec | every field | |
| `<methods>` | member spec | every method | |
| `<1>`,`<2>`… | class names in `-if` | back-reference to the *n*-th wildcard in the condition | |

### Pattern → what it matches

| Pattern | `com.app.MainActivity` | `com.app.ui.LoginActivity` | `MainActivity` (default pkg) | every class |
|---|---|---|---|---|
| `com.app.*` | ✅ | ❌ | ❌ | ❌ |
| `com.app.**` | ✅ | ✅ | ❌ | ❌ |
| `*Activity` | ❌ | ❌ | ✅ | ❌ |
| `**Activity` | ✅ | ✅ | ✅ | ❌ |
| `com.app.**Activity` | ✅ | ✅ | ❌ | ❌ |
| `com.app.?ain*` | ✅ | ❌ | ❌ | ❌ |
| **`*`** | ✅ | ✅ | ✅ | **✅ documented special case** |

> `*` alone matches **every class irrespective of package**. `*` inside a longer pattern does not
> cross `.`. Both are documented; the combination is what catches people.

---

## 4. Class specification grammar

```
-keep[,modifier...] [@annotation] [!]access... [class|interface|enum|@interface] classname
     [extends|implements classname]
[{ member-specification; ... }]
```

| Element | Notes |
|---|---|
| `@annotation` | annotation must be retained (`-keepattributes RuntimeVisibleAnnotations`) or matches nothing |
| access | `public final abstract static private protected synthetic`; `!` negates; multiple are ANDed |
| `class` | matches classes **and** interfaces **and** enums |
| `interface` / `enum` / `@interface` | restrict to that kind |
| classname | fully qualified, **dots**, inner classes use `$` |
| `extends` / `implements` | **synonyms**; matching is transitive |

**Inner classes are separate classes.** `-keep class com.app.Outer` does **not** keep
`com.app.Outer$Inner`. Use `com.app.Outer*` or a second rule.

---

## 5. Member specifications

| Form | Matches |
|---|---|
| `*;` | every field and every method |
| `<fields>;` / `<methods>;` | every field / every method |
| `<init>();` | no-argument constructor |
| `<init>(...);` | every constructor |
| `<init>(java.lang.String);` | that one constructor |
| `<clinit>();` | static initialiser |
| `public *;` | every public member |
| `!private <fields>;` | every non-private field |
| `java.lang.String name;` | that exact field |
| `void set*(***);` | any one-argument setter, any argument type |
| `*** get*();` | any getter, any return type incl. arrays |
| `% isEnabled();` | primitive return type only |
| `void configure(...);` | any argument list |
| `@com.x.Ann <fields>;` | annotated fields |

**R8 full mode (AGP 8 default):** `-keep class Foo` no longer implies keeping `Foo`'s default
constructor. Write `-keep class Foo { <init>(); }`.

---

## 6. Complete directive reference

### Keep family

`-keep` · `-keepclassmembers` · `-keepclasseswithmembers` · `-keepnames` · `-keepclassmembernames` ·
`-keepclasseswithmembernames` — see §1.

### Conditional

| Directive | Meaning |
|---|---|
| `-if <class-spec>` | makes the **next** keep rule conditional; supports `<1>`…`<n>` back-references |

### Attributes

| Directive | Meaning |
|---|---|
| `-keepattributes <list>` | retain the named class-file attributes; comma/space separated; wildcards allowed; **multiple lines accumulate** |
| `-keepparameternames` | retain parameter names in the library API **[PG]** |
| `-renamesourcefileattribute <string>` | overwrite every `SourceFile` value with one constant |
| `-adaptclassstrings [<spec>]` | rewrite string literals that look like renamed class names |
| `-adaptresourcefilenames <filter>` | rename matching resource **files** |
| `-adaptresourcefilecontents <filter>` | rewrite class names inside matching resource file **contents** |

### Negatives

| Directive | Turns off |
|---|---|
| `-dontshrink` | tree shaking |
| `-dontoptimize` | the optimiser |
| `-dontobfuscate` | renaming |
| `-dontpreverify` | preverification (**no-op on Android**) |
| `-dontwarn <spec>` | missing-class warnings for the matched classes |
| `-dontnote <spec>` | notes for the matched classes |
| `-ignorewarnings` | warnings becoming errors, globally |
| `-dontusemixedcaseclassnames` | mixed-case generated names (legacy) |
| `-dontskipnonpubliclibraryclasses` | a legacy optimisation (default since PG 4.5) |

### Diagnostics

| Directive | Output |
|---|---|
| `-printmapping <file>` | `mapping.txt` — original → obfuscated |
| `-printseeds <file>` | `seeds.txt` — everything a keep rule matched |
| `-printusage <file>` | `usage.txt` — everything shrinking removed |
| `-printconfiguration <file>` | the fully merged configuration, with origin comments |
| `-whyareyoukeeping <spec>` | shortest reason chain keeping a matched entity |
| `-verbose` | more detail |
| `-dump <file>` | the internal class structure **[PG]** |

### Optimiser assumptions

| Directive | Meaning |
|---|---|
| `-assumenosideeffects <class-spec>` | calls to the named methods may be deleted — **and their return values replaced** |
| `-assumenoexternalsideeffects` | as above, effects outside the method's own object |
| `-assumenoescapingparameters` | parameters do not escape |
| `-assumenoexternalreturnvalues` | return values do not reference external state |
| `-assumevalues <class-spec>` | a field/method always returns a given value or range |

### Naming and layout

| Directive | Meaning |
|---|---|
| `-obfuscationdictionary <file>` | word list for member names |
| `-classobfuscationdictionary <file>` | word list for class names |
| `-packageobfuscationdictionary <file>` | word list for package names |
| `-overloadaggressively` | reuse names across differing descriptors **[PG]** (R8 ignores) |
| `-useuniqueclassmembernames` | one name per member signature program-wide |
| `-repackageclasses [<pkg>]` | move every renamed class into one package |
| `-flattenpackagehierarchy [<pkg>]` | collapse the package hierarchy to one level |
| `-allowaccessmodification` | let the optimiser widen access modifiers |

### I/O and legacy (never in an AGP project)

`-injars` · `-outjars` · `-libraryjars` · `-include <file>` / `@<file>` · `-basedirectory` ·
`-target` · `-forceprocessing` · `-microedition` · `-android` · `-optimizations <filter>` **[PG]** ·
`-optimizationpasses <n>` **[PG]** · `-skipnonpubliclibraryclasses` · `-keepdirectories`

---

## 7. `-keepattributes` reference

| Attribute | Carries | Keep when | Risk |
|---|---|---|---|
| `Signature` | generic types | GSON `TypeToken`, Retrofit return types, Kotlin reified generics | model shape disclosed |
| `Exceptions` | `throws` clause | reflection over methods, proxies | negligible |
| `InnerClasses` | inner/outer links | `getSimpleName()` | nesting disclosed |
| `EnclosingMethod` | enclosing context | anonymous/local classes | as above |
| `SourceFile` | original filename | resolvable stack traces | **filenames leak unless renamed** |
| `LineNumberTable` | offset → line | resolvable stack traces | low |
| `LocalVariableTable` | **local variable names** | debug builds only | decompiles near source |
| `LocalVariableTypeTable` | as above, generic | debug builds only | as above |
| `MethodParameters` | **parameter names** | name-based binding | vocabulary leak |
| `RuntimeVisibleAnnotations` | class annotations | Retrofit, Room, GSON, DI | **API surface disclosed** |
| `RuntimeVisibleParameterAnnotations` | parameter annotations | Retrofit `@Path` `@Query` | as above |
| `RuntimeVisibleTypeAnnotations` | type-use annotations | rare | low |
| `RuntimeInvisible*` | build-time-only annotations | almost never | low |
| `AnnotationDefault` | annotation defaults | custom annotations with defaults | low |
| `Deprecated`, `Synthetic` | markers | never | none |
| `*Annotation*` | wildcard over all six annotation attributes | common shorthand | keeps more than needed |

**The stack-trace pair:**

```proguard
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
```

---

## 8. The rules everyone needs, correct forms

```proguard
# entry points -- AGP generates these from the manifest; do not write them by hand
# (build/intermediates/aapt_proguard_file/<variant>/aapt_rules.txt)

# native methods
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# enums used by name
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Parcelable
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

# Java serialisation
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# GSON, done properly: annotate the fields and keep the annotated ones
-keepattributes Signature, RuntimeVisibleAnnotations
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# one reflectively loaded class -- narrow, with its constructor named for full mode
-keep class com.example.PluginEntry { <init>(); }

# strip verbose logging (NOT Log.w / Log.e -- keep your error logging)
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# stack traces
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
```

---

## 9. Anti-patterns

| Rule | What it really does |
|---|---|
| `-keep class com.app.** { *; }` | disables shrinking, renaming **and** optimisation for the namespace; ships dead code |
| `-keep class *` | keeps every class in the program |
| `-keepclassmembers class * { *; }` | keeps every member of every class |
| `-dontobfuscate` | ships every original name; usually a wrong fix for crash reports |
| `-dontwarn **` | hides "this dependency is incomplete", which becomes `NoClassDefFoundError` |
| `-keepattributes *` | keeps `LocalVariableTable` if present — original local variable names |
| `-keepattributes SourceFile` alone | ships original `.java`/`.kt` filenames **[PG]** |
| `-keep class *Activity` | matches only the **default package**; almost certainly matches nothing |
| `-dontpreverify`, `-optimizationpasses N`, `-microedition` | no-ops on Android; a copy-paste tell |
| `-ignorewarnings` | build-time error becomes production crash |

---

## 10. Where rules come from (merged, in this order)

1. `getDefaultProguardFile("proguard-android-optimize.txt")` — SDK defaults
2. `app/build/intermediates/aapt_proguard_file/<variant>/aapt_rules.txt` — manifest + layout keeps
3. every dependency's consumer rules: AAR `proguard.txt`, JAR `META-INF/proguard/*.pro`
4. your `proguardFiles` (`app/proguard-rules.pro`)
5. R8's built-in assumptions

**Keep rules are additive. There is no "unkeep".** A dependency's keep cannot be removed from your
build.

| Build-file property | Applies to | Ships to consumers |
|---|---|---|
| `proguardFiles` | this module | no |
| `consumerProguardFiles` | nothing at build time | **yes**, into every dependent app |
| `testProguardFiles` | the test APK | no |

---

## 11. Build outputs

| Path | Contents |
|---|---|
| `app/build/outputs/mapping/<variant>/mapping.txt` | original → obfuscated |
| `…/seeds.txt` | everything a keep rule matched |
| `…/usage.txt` | everything shrinking removed |
| `…/configuration.txt` | **every rule the build used, merged, with origins** |
| `app/build/intermediates/aapt_proguard_file/<variant>/aapt_rules.txt` | AGP's generated keeps |

---

## 12. Commands

```bash
# host — R8 and D8 both live inside build-tools/<ver>/lib/d8.jar. No separate r8.jar. No ProGuard.
BT=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
java -cp "$BT/lib/d8.jar" com.android.tools.r8.R8 --version
java -cp "$BT/lib/d8.jar" com.android.tools.r8.R8 --help

# host — run R8 by hand
java -cp "$BT/lib/d8.jar" com.android.tools.r8.R8 \
  --lib "$ANDROID_HOME/platforms/android-35/android.jar" --min-api 21 --release \
  --pg-conf rules.pro --pg-map-output mapping.txt --pg-conf-output configuration.txt \
  --output out/ $(find classes -name '*.class')

# host — de-obfuscate a stack trace
java -cp "$BT/lib/d8.jar" com.android.tools.r8.retrace.Retrace mapping.txt trace.txt

# host — the merged configuration from a Gradle build
./gradlew :app:assembleRelease
less app/build/outputs/mapping/release/configuration.txt

# host — what fraction of a mapping is identity (i.e. renaming did nothing)
awk -F' -> ' '/^[^ ].*:$/ {t++; if ($1 == substr($2,1,length($2)-1)) i++} \
  END {printf "%d/%d identity (%.0f%%)\n", i, t, 100*i/t}' mapping.txt

# host — rules files a dependency imposes on you
find ~/.gradle/caches/modules-2 -name '*.aar' | while read -r a; do
  unzip -l "$a" 2>/dev/null | grep -q proguard.txt && { echo "== $a"; unzip -p "$a" proguard.txt; }
done

# host — build artefacts that must not be in an APK
unzip -l app.apk | grep -iE 'mapping\.txt|seeds\.txt|usage\.txt|configuration\.txt|\.pro$|\.jobf$'

# host — apply a recovered mapping in jadx
jadx -Prename-mappings.format=PROGUARD_FILE --mappings-path mapping.txt -d out app.apk

# host — JNI symbols: post-rename Java class names, in the clear
unzip -p app.apk 'lib/*/*.so' | strings -a | grep -E '^Java_' | sort -u

# host — resource names: never renamed at any setting
aapt2 dump resources app.apk | grep -oE '(layout|id|string)/[a-z0-9_]+' | sort -u

# host — original source filenames, if any shipped
unzip -p app.apk classes.dex | strings -a | grep -E '\.(java|kt)$' | sort -u
```

### This chapter's scripts

```bash
python3 -B scripts/proguard-rules-audit.py rules.pro                 # what each rule preserves, how broad
python3 -B scripts/proguard-rules-audit.py configuration.txt --min-severity MEDIUM
python3 -B scripts/proguard-rules-audit.py rules.pro --fail-on HIGH  # CI gate
python3 -B scripts/what-survived.py app.apk                          # name census
python3 -B scripts/what-survived.py app.apk --rules rules.pro        # + rule correlation
python3 -B scripts/what-survived.py app.apk --json                   # machine-readable
frida -U -f com.the.app -l scripts/frida-keep-census.js              # runtime census + shape search
```

---

## 13. Grep catalogue

| Looking for | Command |
|---|---|
| The canonical defect | `grep -nE '\-keep[a-z]* .*\*\*.*\{\s*\*\s*;\s*\}' rules.pro` |
| Any package-crossing keep | `grep -nE '\-keep[a-z]*.*\*\*' rules.pro` |
| Global switches off | `grep -nE '^\s*-(dontshrink\|dontobfuscate\|dontoptimize\|ignorewarnings)' rules.pro` |
| Blanket warning suppression | `grep -nE '^\s*-dontwarn\s+\*\*?\s*$' rules.pro` |
| Attributes kept wholesale | `grep -nE '^\s*-keepattributes\s+\*' rules.pro` |
| `SourceFile` without a rename | `grep -q SourceFile rules.pro && ! grep -q renamesourcefileattribute rules.pro && echo LEAK` |
| Debug attributes in release | `grep -nE 'LocalVariable(Type)?Table\|MethodParameters' rules.pro` |
| Copy-from-a-Java-project tell | `grep -nE '\-(dontpreverify\|microedition\|optimizationpasses\|dontusemixedcaseclassnames)' rules.pro` |
| Optimiser assumptions | `grep -nE -A5 '\-assume(nosideeffects\|values)' rules.pro` |
| Rules files anywhere in a repo | `find . -name '*.pro' -o -name 'proguard*.txt' -o -name 'proguard*.cfg'` |
| Minification settings | `grep -rn 'minifyEnabled\|isMinifyEnabled\|proguardFiles\|consumerProguardFiles' --include='*.gradle*' .` |

---

## 14. Recognising a configuration from the output

| Observation | Configuration |
|---|---|
| Everything unrenamed, dead code present, original `.java` filenames | minification **off** |
| Everything unrenamed, dead code removed, no filenames | `-dontobfuscate` |
| `mapping.txt` is all `X -> X` | renaming disabled |
| One package unrenamed, dependencies mangled | package-scoped `-keep` |
| Class unrenamed, body empty | `keepclasseswithmembernames` whose trigger member was shrunk |
| Only classes with native methods unrenamed | the JNI rule |
| Only manifest components unrenamed | AGP's generated keeps only — **the well-configured case** |
| Model classes unrenamed, `Signature` intact | GSON/Retrofit keeps |
| Class renamed but some members not | `-keepclassmembers` |
| `pNNN` packages, `CNNNN` classes in jadx | jadx's own renaming of obfuscated identifiers |

---

## 15. Version matrix

| AGP | Engine | Note |
|---|---|---|
| ≤ 3.3 | ProGuard | rules tuned to ProGuard semantics |
| 3.4 – 3.6 | R8 | `useProguard = true` reverts |
| 4.0 – 4.2 | R8 | `android.enableR8=false` is the last escape hatch |
| 7.0 – 7.4 | R8 compat | no way back; `android.enableR8.fullMode=true` opts in |
| **8.0+** | **R8 full mode** | default; `android.enableR8.fullMode=false` opts out |

| Behaviour | ProGuard | R8 compat | R8 full |
|---|---|---|---|
| `-keep class Foo` keeps default constructor | ✅ | ✅ | **❌** |
| `-optimizations`, `-optimizationpasses` | ✅ | ignored | ignored |
| `-overloadaggressively` | ✅ | ignored | ignored |
| Missing classes | warning | warning | **error** unless `-dontwarn` |
| Enum unboxing, class merging, argument removal | limited | ✅ | ✅ more |
| Kotlin metadata rewriting | ❌ | ✅ | ✅ |
| `Class.forName(<constant>)` resolved and rewritten | ❌ | ✅ | ✅ *(measured, R8 8.6.2)* |
| `getDeclaredField(<constant>)` modelled | ❌ | ❌ | **❌** *(measured — write the keep)* |

---

## 16. Measured facts (this chapter's fixture, R8 8.6.2, build-tools 35.0.1)

| Fact | Value |
|---|---|
| Same app, no rules → tightened rules | `classes.dex` 7,384 B → **2,920 B**; 12 classes → **4**; 50 named members → **10** |
| Same app, over-broad rules | 7,180 B, 12 classes, 49 named members — i.e. ≈ no rules |
| APK sizes, all three builds | **identical (12,757 B)** — `apksigner` pads the signing block to a 4096-byte boundary. Compare `classes.dex`, never the APK |
| Original `.java` filenames in the DEX | **7 in the unminified build, 0 in both minified builds** — R8 overwrites `SourceFile` by default even with `-keepattributes *` and `-dontobfuscate` |
| `staging-token-do-not-ship` (dead-code constant) | present without rules, **absent with tightened rules**, present with over-broad rules |
| Enum `Kind.name()` | constant-folded to the literal `"PURCHASE"` in the DEX |
| Native-method rule | keeps a class name whose native method shrinking then removed, leaving an **empty class with its original name** |
| `Class.forName(<constant>)` with the keep deleted | class **survives**, renamed `a.a`; call rewritten to `const-class` |
| System app on the test device (`GoogleFeedback.apk`) | 315 classes, **1.3% renamed** — platform builds shrink but do not obfuscate |
| Commercial app on the test device (22.8 MB) | 18,447 classes, **52.5% renamed**; 68 URLs and 42,451 long strings untouched; 4 Java class names exposed via JNI symbols |
