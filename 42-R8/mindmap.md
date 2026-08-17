# 42 — R8 mind map

One map of the whole chapter. Detail in [README.md](README.md), lookup tables in [cheatsheet.md](cheatsheet.md).

```mermaid
mindmap
  root((R8))
    1. What it is
      Whole-program optimiser + DEX compiler
      Lives inside build-tools/lib/d8.jar
        No separate r8.jar exists
        com.android.tools.r8.R8
        Same jar as D8, same build hash
      Default since AGP 3.4
        ProGuard option removed in AGP 7.0
      Replaced ProGuard plus dx
      A compiler that renames
        NOT a renamer that deletes
    2. The three jobs
      Shrinking
        Removes unreachable code
        Defends the 64K method-id limit
      Optimisation
        Rewrites reachable code smaller
      Obfuscation
        Renames identifiers only
        The only hardening part
      Plus desugaring
        Lambdas, default methods, java.time
    3. Four phases in order
      Enqueuer
        Root set, then transitive reachability
        Roots come from FOUR sources
          proguard-rules.pro
          every AAR consumer-rules.pro
          AGP generated rules
          SDK proguard-android-optimize.txt
        configuration.txt is the merged truth
      Optimiser
        Inlining
          Methods vanish entirely
          One runtime frame, many source frames
        Class merging
          Vertical: into the sole subclass
          Horizontal: siblings fused, switch on an int
        Enum unboxing
          Enum becomes int
          Leaves EnumUnboxingSharedUtility
        Outlining
          Duplicated sequences extracted
          Opposite of inlining, same goal
        Constant propagation
      Minifier
        Runs AFTER optimisation
        Names NOT stable across builds
        Overloading exploited aggressively
        Graph colouring over the hierarchy
      DEX writer
        Desugars to min-api
        Emits SYNTHETIC line numbers
        Splits across classesN.dex
    4. mapping.txt
      Not a dictionary
      A record of optimiser decisions
      Indentation is syntax
        Column zero is a class
        Indented is a member
        Read right to left
      Header
        compiler, compiler_version
        min_api, compiler_hash
        pg_map_id
          Match vs ExtractMarker to prove pairing
        pg_map_hash
      Method line grammar
        obfStart colon obfEnd
        inlineOwner qualifier
        trailing srcStart srcEnd
      Line arithmetic
        srcStart equals srcEnd, use srcStart
        else srcStart plus L minus obfStart
        zero means unknown
      Inline chains
        Same range, same target name
        INNERMOST FIRST
        Leaf has two trailing numbers
        Callers have one
        Source file from the OWNER
      Special entries
        R8$$REMOVED$$CLASS$$n
          Not in the APK at all
        residualsignature
          Signature in the SHIPPED program
        r8.synthesized marker
        sourceFile restores erased names
      Siblings that also leak
        seeds.txt
        usage.txt
        configuration.txt
    5. Synthetic vocabulary
      Every $$ marks compiler output
      Original name is LEFT of the marker
      Desugaring
        Foo$$ExternalSyntheticLambda0
        Foo$$InternalSyntheticLambda hash
          Content hash is BUILD STABLE
        $r8$lambda$
      Optimisation
        $$ExternalSyntheticOutline
        $$ExternalSyntheticApiModelOutline
        $$ExternalSyntheticBackport
        Foo$EnumUnboxingSharedUtility
      Access bridges
        $$Nest$mFoo and $$Nest$fFoo
          Leaks owner AND member
        access$000 from javac
        access$name from kotlinc
          Leaks the private member name
      kotlinc constructs
        Foo$WhenMappings
        Foo$Companion
        Foo$DefaultImpls
        foo$default
        Foo$bar$lambda$0
      Schemes CHANGE between versions
        Dates the build
        Breaks naive diffs
        Read compiler_version first
    6. Full mode
      CLI default; AGP default from 8.0
      android.enableR8.fullMode
      Reads -keep narrowly
      Assumes no reflection
      More merging, unboxing, devirtualisation
      Measured 2.6x smaller than compat
      Breaks apps at RUNTIME only
    7. kotlin.Metadata
      Why it exists
        JVM cannot express Kotlin types
        Read by kotlin-reflect at runtime
        Therefore readable by you statically
      Structure
        k kind, mv version
        d1 protobuf payload
        d2 plaintext string table
        xs xi pn
      d1 encoding
        U+0000 modern, low byte per code unit
        U+FFFF legacy 8-to-7
        MUTF-8 trap kills naive decoders
      FOUR measured states
        Stripped, R8 default both modes
        Payload stripped, empty shell
          grep gives false positives
        Rewritten when kept
          Class and function names obfuscated
          PROPERTY NAMES SURVIVE
        Intact, but class was never renamed
      Why properties survive
        R8 renames JVM members
        A Kotlin property is not one
        Backed by field plus getter plus setter
        No single new name to write
      Measured reality
        19 APKs, 316k classes
        10 had no metadata at all
        0 wholesale recoveries
        87 property names in the best case
    8. Security
      Hardening control, NOT a boundary
      Never protected
        String constants
        Resources and manifest names
        JNI symbols
        Framework call graph
        Runtime behaviour
      MASVS
        RESILIENCE-3 and RESILIENCE-4
        CODE-4 release settings
      Severity
        Absence is informational or low
        Leaked mapping is Medium
        Report the SECRET not the obfuscation
        aab proguard.map is NOT a finding
      Developer failure modes
        keep class com.app.** with wildcards
        Disabling minify to fix a crash
        Shipping the mapping file
        Believing renaming hides a key
    9. Analysis workflow
      ExtractMarker first
        R8 vs D8 only
        version, min-api, pg-map-id
      Hunt the mapping by CONTENT not name
      Metadata verdict, then --members
      Measure the app's OWN package
        Bimodal distribution check
        Simple-name reuse check
      Retrace before any structural claim
      Hook by structure, never by name
```

---

## How to use this map

Four reading orders, depending on why you are here.

| You are | Read the branches in this order |
|---|---|
| Learning R8 for the first time | 1 → 2 → 3 → 6 |
| Reading an obfuscated APK | 9 → 5 → 7 → 4 |
| Holding a leaked `mapping.txt` | 4 → 8 |
| Writing a report | 8 → 9 |

The three branches that carry the chapter's actual contribution — the parts you will not find stated correctly elsewhere — are **4 (inline chains and the line arithmetic)**, **5 (the naming schemes and what each leaks)**, and **7 (the four metadata states, and why properties survive rewriting)**.
