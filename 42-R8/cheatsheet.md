# 42 — R8 cheat sheet

Dense reference. Prose lives in [README.md](README.md).

---

## 1. Where R8 is, and how to run it

| Fact | Value |
|---|---|
| Location | `$ANDROID_HOME/build-tools/<ver>/lib/d8.jar` — **there is no `r8.jar`** |
| R8 main class | `com.android.tools.r8.R8` |
| D8 main class | `com.android.tools.r8.D8` |
| Retrace main class | `com.android.tools.r8.retrace.Retrace` |
| Marker reader | `com.android.tools.r8.ExtractMarker` |
| Default since | AGP 3.4.0; ProGuard option removed in AGP 7.0 |
| Full mode | **CLI default**; `--pg-compat` opts into compatibility mode |
| AGP full mode | `android.enableR8.fullMode=true` — default from AGP 8.0 |
| JDK ceiling | R8 8.6.x cannot read class files above **Java 21** |

```bash
java -cp "$SDK/build-tools/35.0.1/lib/d8.jar" com.android.tools.r8.R8 --version
java -cp "$SDK/build-tools/35.0.1/lib/d8.jar" com.android.tools.r8.R8 \
  --release --min-api 33 --lib "$SDK/platforms/android-35/android.jar" \
  --pg-conf rules.pro --pg-map-output mapping.txt --output out/ app.jar libs.jar
```

### R8 CLI flags

| Flag | Effect |
|---|---|
| `--release` / `--debug` | Without / with debugging info (release is default) |
| `--dex` / `--classfile` | DEX output (default) / JVM class output |
| `--min-api <n>` | Desugaring target |
| `--lib <file\|jdk-home>` | Library (framework) input — never renamed, never emitted |
| `--classpath <file>` | Classpath input — not emitted |
| `--pg-conf <file>` | Keep rules |
| `--pg-conf-output <file>` | Write the merged rule set (the `configuration.txt` equivalent) |
| `--pg-map-output <file>` | Write `mapping.txt` |
| `--pg-map <file>` | Read a previous mapping (`-applymapping`) for stable names |
| `--pg-compat` | Compatibility mode |
| `--no-tree-shaking` | Disable shrinking |
| `--no-minification` | Disable renaming |
| `--no-desugaring` | Disable desugaring |
| `--main-dex-rules <file>` | Keep rules for the primary DEX |
| `--android-resources <in> <out>` | Resource shrinking |

---

## 2. `mapping.txt` grammar

**Indentation is syntax.** Column zero = class; indented = member.

```
# <header comments, all lines start with #>

<original.Class> -> <obf.Class>:
# {"id":"sourceFile","fileName":"<Original.kt>"}
    <type> <origField> -> <obfField>
      # {"id":"com.android.tools.r8.residualsignature","signature":"<desc>"}
    <ret> <origMethod>(<args>) -> <obfMethod>
    <os>:<oe>:<ret> [<inlineOwner>.]<origMethod>(<args>)[:<ls>[:<le>]] -> <obfMethod>
      # {"id":"com.android.tools.r8.synthesized"}
```

### Header lines

| Header | Meaning |
|---|---|
| `# compiler:` | `R8` or `ProGuard` |
| `# compiler_version:` | Exact version — dates the build, selects the synthetic naming scheme |
| `# min_api:` | The `minSdkVersion` compiled for |
| `# compiler_hash:` | R8 build hash |
| `# {"id":"com.android.tools.r8.mapping","version":"2.2"}` | Mapping format version |
| `# pg_map_id:` | Short id — **match against the APK's R8 marker to prove the pairing** |
| `# pg_map_hash: SHA-256 ...` | Hash of the mapping content |

### Method-line fields

| Part | Present when | Meaning |
|---|---|---|
| `<os>:<oe>:` | Line info retained | Obfuscated line range |
| `<ret>` | Always | Return type (original) |
| `<inlineOwner>.` | Frame was **inlined in from another class** | The method's true owner |
| `(<args>)` | Method (absent for fields) | Original parameter types |
| `:<ls>` only | **Caller** frame in an inline chain | Original line, exactly |
| `:<ls>:<le>` | **Innermost** frame | Original line range |
| `-> <obfMethod>` | Always | Name in the APK |

### Line-number arithmetic

| Case | Original line |
|---|---|
| `ls == le` | `ls` — the whole obfuscated range maps to one source line |
| `ls != le` | `ls + (L - os)` |
| Single `:ls` (caller frame) | `ls` |
| `0` | Unknown — print no line number |

### Inline chains

> Consecutive member lines sharing **the same `<os>:<oe>` AND the same `-> <obfName>`** are ONE inline chain, listed **innermost first**. The innermost entry has **two** trailing line numbers; every caller has **one**.

```
    130:146:int com.app.Vault.tierWeight(com.app.Tier):56:56 -> main   <- innermost
    130:146:int com.app.Vault.computeCode(com.app.Record):70 -> main   <- caller
    130:146:void main(java.lang.String[]):119 -> main                  <- caller
```

Source file for an inlined frame comes from the **owner's** class entry; if the owner has no entry, R8 synthesises `<SimpleName>.java`.

### Special class names in a mapping

| Name | Meaning |
|---|---|
| `R8$$REMOVED$$CLASS$$<n>` | Class deleted from the output entirely. **Not in the APK.** Entry exists only so its members retrace |
| `<Class> -> <Class>:` (identical) | A keep rule forbade renaming |
| `sourceFile: R8$$SyntheticClass` | R8 invented this class |
| `# {"id":"com.android.tools.r8.synthesized"}` | This class/member is compiler-generated |
| `residualsignature` | The member's signature **in the shipped program** after unboxing / argument removal |

> A class that is never referenced at all is dropped **with no mapping entry**. `R8$$REMOVED` requires the class to have been referenced.

---

## 3. Synthetic-name decoder

| Pattern | Generated by | Original construct | Name it leaks |
|---|---|---|---|
| `Foo$$ExternalSyntheticLambda<n>` | D8/R8 desugar | Lambda / method ref in `Foo` | **`Foo`** |
| `Foo$$InternalSyntheticLambda$<n>$<64hex>$<m>` | D8/R8 desugar | Lambda needing content identity | **`Foo`** + a **build-stable** hash |
| `$r8$lambda$<hash>` | R8 | Method holding a lambda body | — |
| `Foo$$ExternalSyntheticOutline<n>` | R8 outlining | *Nothing* — a shared fragment | **`Foo`** (misleading; not one source construct) |
| `Foo$$ExternalSyntheticApiModelOutline<n>` | R8 | API-level-guarded call, outlined | **`Foo`** |
| `Foo$$ExternalSyntheticBackport<n>` | R8 | A newer JDK method backported | **`Foo`** |
| `Foo$EnumUnboxingSharedUtility` | R8 | Enum `Foo` replaced by `int` | **`Foo`**, the enum type name |
| `Foo$$Nest$mBar` | Nest desugaring | Private **method** `Bar` of `Foo` | **`Foo`** and **`Bar`** |
| `Foo$$Nest$fBar` | Nest desugaring | Private **field** `Bar` of `Foo` | **`Foo`** and **`Bar`** |
| `access$000`, `access$100` | **javac** | Inner-class access to a private outer member | — (counter only) |
| `access$<name>` | **kotlinc** | Same | **the private member's name** |
| `Foo$WhenMappings` | kotlinc | `when` over an enum inside `Foo` | **`Foo`** |
| `Foo$Companion` | kotlinc | `companion object` | **`Foo`** |
| `Foo$DefaultImpls` | kotlinc | Interface default methods | **`Foo`** |
| `foo$default(...)` | kotlinc | Default-parameter bridge | **`foo`** |
| `Foo$bar$lambda$<n>` | kotlinc | Lambda body lifted to a method | **`Foo`** and **`bar`** |
| `this$0`, `val$x` | javac | Outer instance / captured local | — |

**Rule of thumb:** every `$$` marks a compiler-constructed name; the developer's identifier is to the **left** of the marker.

> **These spellings are version-dependent.** `$$Lambda$Foo$0` (older) became `Foo$$ExternalSyntheticLambda0`. Read `# compiler_version:` or run `ExtractMarker` before trusting a name-shape heuristic or diffing two builds.

---

## 4. Keep-rule effects on R8's three phases

| Rule | Survives shrinking | Immune to optimisation | Keeps its name |
|---|---|---|---|
| `-keep class X { *; }` | yes | yes | **yes** |
| `-keep,allowobfuscation class X { *; }` | yes | yes | **no** |
| `-keep,allowshrinking class X` | no | — | yes |
| `-keepnames class X` | no | — | yes |
| `-keepclassmembers class X { ... }` | only if X survives | yes | yes |
| `-keepclasseswithmembers` | conditional | — | — |
| `-if ... -keep ...` | conditional | — | — |
| `-checkdiscard class X` | **fails the build if X survives** | — | — |

Rule sources merged into the root set: `proguard-rules.pro` + every AAR's `consumer-rules.pro` + AGP-generated rules + the SDK's `proguard-android-optimize.txt`. **`build/outputs/mapping/release/configuration.txt` is the merged truth.**

---

## 5. Build outputs and where they must not go

| File | Contents | Ships? |
|---|---|---|
| `mapping.txt` | Full de-obfuscation key + structure | **Never** |
| `seeds.txt` | Everything a keep rule matched — the reflective surface | **Never** |
| `usage.txt` | Everything R8 deleted | **Never** |
| `configuration.txt` | Merged rule set — enumerates every SDK | **Never** |
| `BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map` inside an `.aab` | The mapping | **Correct — never reaches a device. Not a finding** |

---

## 6. Triage commands

```bash
# Which compiler, version, min-api, pg-map-id?
java -cp "$D8" com.android.tools.r8.ExtractMarker target.apk

# Mapping shipped inside the APK? By NAME:
unzip -l target.apk | grep -Ei 'mapping|seeds|usage|configuration|\.map$|proguard'

# ...and by CONTENT (the incident version is rarely called mapping.txt):
for f in $(unzip -Z1 target.apk); do
  unzip -p target.apk "$f" 2>/dev/null | head -c 4096 \
    | grep -qE '^# compiler: (R8|ProGuard)|^# pg_map_id:' && echo "MAPPING CONTENT: $f"
done

# Kotlin metadata verdict / recovery
python3 -B scripts/kotlin-metadata-recover.py target.apk --rewrite-check
python3 -B scripts/kotlin-metadata-recover.py target.apk --members
python3 -B scripts/kotlin-metadata-recover.py target.apk --json

# Mapping file: what it discloses, lookups, retrace
python3 -B scripts/mapping-reader.py map.txt stats
python3 -B scripts/mapping-reader.py map.txt lookup a.b.c
python3 -B scripts/mapping-reader.py map.txt reverse verifyLicence
python3 -B scripts/mapping-reader.py map.txt retrace crash.txt
adb logcat -d -b crash | python3 -B scripts/mapping-reader.py map.txt retrace

# Official retrace
java -cp "$D8" com.android.tools.r8.retrace.Retrace map.txt crash.txt

# Source-side review
grep -rn "minifyEnabled\|isMinifyEnabled" --include="build.gradle*" .
grep -rn "enableR8.fullMode" gradle.properties
grep -rn -- "-keep" --include="*.pro" . | grep -E '\*\*\s*\{\s*\*;\s*\}'
git log --all --oneline -- '**/mapping.txt' '**/proguard.map'
```

---

## 7. `kotlin.Metadata` — the four states

| State | Detection | Recovery |
|---|---|---|
| **Stripped** (R8 default, both modes) | `Lkotlin/Metadata;` absent from the DEX | None |
| **Payload stripped** (empty shell) | Annotation present, **all elements absent** | None — and `grep` reports a false positive |
| **Rewritten** (`kotlin.Metadata` kept + class renamed) | Verdict `rewritten`; class/function names are 1–2 chars | **Kotlin PROPERTY names survive** |
| **Intact** (class not renamed) | Verdict `intact`; names are long | Everything, but the class was never renamed anyway |

### Annotation elements

| Element | Content |
|---|---|
| `k` | 1 class · 2 file facade · 3 synthetic class · 4 multi-file facade · 5 multi-file part |
| `mv` | Metadata version |
| `d1` | Protobuf payload (encoded) |
| `d2` | String table (plaintext) |
| `xs` / `xi` / `pn` | Extra string / flags / package name |

### `d1` encoding, selected by the first code unit of `d1[0]`

| Marker | Mode | Decode |
|---|---|---|
| `U+0000` | Modern (`bytesToStrings`) | Drop marker; take the low byte of each code unit |
| `U+FFFF` | Legacy 8-to-7 | Drop marker; add `0x7F` mod `0x7F`; unpack 7 bits into 8 |

Decoded layout: `[varint len][JvmProtoBuf.StringTableTypes][ProtoBuf.Class | Package]`.
For `k=3` the payload is a bare `ProtoBuf.Function`. For `k=4` `d1` is **not** encoded at all — it is a plain array of the parts' JVM names.

| Message | Field | # |
|---|---|---|
| `Class.fq_name` | class name index | 3 |
| `Class.constructor/function/property` | members | 8 / 9 / 10 |
| `Class.enum_entry` | enum constants | 13 |
| `Function.name` / `Property.name` | member name index | 2 |
| `Function` jvm ext `method_signature` | JVM name+desc | 100 |
| `Property` jvm ext `property_signature` | field/getter/setter | 100 |

> **Why properties leak:** R8 renames JVM members. A Kotlin function maps 1:1 to a JVM method, so R8 rewrites `Function.name`. A Kotlin **property** is backed by up to three JVM members, so there is no single new name for `Property.name` — R8 updates the JVM signature extension and leaves the Kotlin name alone.

> **`grep -rn 'Lkotlin/Metadata;'` is not a test.** A string in the DEX string table proves a reference exists, not that any class carries the annotation with data.

---

## 8. Measuring obfuscation coverage

Measure the **app's own package**, never the whole APK (dependencies dominate the average).

| Short-name (≤3 chars) proportion | Reading |
|---|---|
| > 80% | Applied and effective |
| 20–80% | Partial — identify which packages are exempt and why |
| < 20% **with** `~R8` marker | **Finding:** keep rules neutered renaming |
| < 20% **without** `~R8` marker | `minifyEnabled false` — informational |

Cross-checks that defend the heuristic:
- Length distribution should be **bimodal**, with a spike at 1–2 chars.
- Simple names should be **reused** across many packages.
- Defeated by `-obfuscationdictionary` (plausible words) — the reuse check still works.

---

## 9. Severity

| Finding | Default |
|---|---|
| `minifyEnabled false` | Informational / Low |
| Over-broad keep rules leave the app unobfuscated | Low |
| `kotlin.Metadata` property names recoverable | Informational / Low |
| `SourceFile` / line-number attributes retained | Informational |
| **`mapping.txt` inside the APK** | **Medium** |
| **`mapping.txt` on a public endpoint** | **Medium** |
| A secret recovered because obfuscation was its only control | **Report the secret, not the obfuscation** |
| `proguard.map` inside an `.aab` | **Not a finding** |

MASVS: **RESILIENCE-3** (anti-tampering and obfuscation), **RESILIENCE-4** (impeding comprehension), **CODE-4** (release build settings).

---

## 10. What R8 never protects

String constants · resources and `resources.arsc` · manifest component names · JNI symbol names (`Java_com_app_Foo_bar`) · the framework/JDK call graph · native `.so` code · runtime behaviour.

---

## 11. Recognising R8 output in ten seconds

| Signal | Means |
|---|---|
| `~R8{...}` marker | R8 ran |
| `~D8{...}` only | Dexed, **not** minified |
| `$$ExternalSyntheticLambda` | D8/R8 desugaring |
| `$r8$lambda$`, `$$InternalSyntheticLambda` | R8 specifically |
| `EnumUnboxingSharedUtility` | R8 optimisation on — suggests full mode |
| Every class's `source_file_idx` = `"SourceFile"` | Shrinking applied, file attribute flattened |
| Classes `a`, `b`, `c` in packages `a`, `b` | Renaming applied |
| `Lkotlin/Metadata;` in the string table | Kotlin **and** something kept the annotation type — check the payload |

---

## 12. Gotchas

| Gotcha | Reality |
|---|---|
| R8 names stable across builds | **No.** Invalidates cross-version mappings, name-based hooks, name-based diffs |
| Release stack-trace line numbers are source lines | **No.** They are keys into the mapping table |
| A one-frame trace means a shallow stack | **No.** Inlining collapses frames |
| `mapping.txt` line count = class count | **No.** It lists removed classes and omits R8-invented ones |
| `-keepattributes *Annotation*` preserves `kotlin.Metadata` | **No.** The annotation *type* is shrunk away |
| Synthetic members are authored code | **No.** Filter on `ACC_SYNTHETIC` (`0x1000`) |
| `Unsupported class file major version NN` is an R8 bug | **No.** Your JDK is newer than R8 can read; use JDK 21 or lower |
| Obfuscation absent = vulnerability | **No.** Missing hardening control |
