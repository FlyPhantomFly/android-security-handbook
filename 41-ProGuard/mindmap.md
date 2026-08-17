# 41 — ProGuard — mind map

One map of the whole chapter. Read it outward from the centre: the **lineage** explains why the
language looks the way it does, the **language** is what you actually read and write, the
**pipeline** explains what each rule does mechanically, the **survivors** are what no rule can
remove, and **assessment** is what you do with all of it.

```mermaid
mindmap
  root((41 ProGuard))
    Lineage
      "2002 Java shrinker by Eric Lafortune"
      "2009 bundled with the Android SDK"
      "2019 AGP 3.4 - R8 becomes default"
      "2021 AGP 7.0 - ProGuard no longer selectable"
      "2023 AGP 8.0 - R8 full mode default"
      "DexGuard is the paid descendant"
      "The file is still proguard-rules.pro"
      "Not in the SDK - R8 lives in build-tools/lib/d8.jar"
    The four phases
      Shrink
        "reachability from keep roots"
        "-dontshrink turns it off"
        "usage.txt lists what went"
      Optimise
        inline
        class merging
        enum unboxing
        argument removal
        "-dontoptimize turns it off"
        "R8 ignores -optimizations"
      Obfuscate
        "a b c aa ab ..."
        "package renamed too"
        "-dontobfuscate turns it off"
        "mapping.txt records it"
      Preverify
        "no-op on Android"
        "a copy-paste tell"
    The language
      Six keep directives
        "-keep : class + members, presence + name"
        "-keepclassmembers : members only"
        "-keepclasseswithmembers : conditional"
        "-keepnames = -keep,allowshrinking"
        "-keepclassmembernames"
        "-keepclasseswithmembernames"
      Decoder
        "contains 'names' - cannot stop deletion"
        "contains 'classmembers' - class unprotected"
      Modifiers
        allowshrinking
        allowobfuscation
        allowoptimization
        includedescriptorclasses
        includecode
      Wildcards
        "? one character"
        "* does NOT cross the dot"
        "** DOES cross the dot"
        "*** any type incl arrays"
        "% any primitive"
        "... any argument list"
        "bare * matches every class"
      Members
        "*;"
        "<init> <clinit>"
        "<fields> <methods>"
        "annotations select members"
      Conditional
        "-if with <1> back-references"
      Attributes
        Signature
        "SourceFile + renamesourcefileattribute"
        LineNumberTable
        RuntimeVisibleAnnotations
        "LocalVariableTable - debug only"
      Negatives
        dontshrink
        dontobfuscate
        dontoptimize
        "dontwarn - scope it"
        ignorewarnings
      Diagnostics
        printmapping
        printseeds
        printusage
        printconfiguration
        whyareyoukeeping
      Assumptions
        "assumenosideeffects - deletes calls AND return values"
        "assumevalues - deletes branches"
    Where rules come from
      "your proguard-rules.pro"
      "AGP aapt_rules.txt from the manifest"
      "SDK proguard-android-optimize.txt"
      "every AAR's consumer proguard.txt"
      "R8 built-in assumptions"
      "keeps are ADDITIVE - there is no unkeep"
      "configuration.txt is the only full record"
    What survives renaming
      "string constants"
      "resource names in resources.arsc"
      "framework and JDK symbols"
      "manifest component names"
      "JNI symbols in .so files"
      "runtime-visible annotation values"
      "enum constant names when kept"
      "kotlin.Metadata"
      "class hierarchy and descriptors"
      "a shipped mapping.txt"
    Reading the output
      "one package intact - a scoped keep"
      "all intact + dead code - minify off"
      "all intact + shrunk - dontobfuscate"
      "identity mapping.txt - renaming disabled"
      "empty unrenamed class - keepclasseswithmembernames artefact"
      "only components intact - well configured"
      "pNNN packages - jadx renaming, not the obfuscator"
    Assessment
      Method
        "census the APK"
        "scope to the app package - and mind the moved classes"
        "correlate survivors to rules"
        "check for shipped mapping.txt"
        "read configuration.txt not your own file"
      Severity
        "hardening, not vulnerability"
        "state the threat model first"
        "never a remediation for a real defect"
        "over-broad keep beats 'no obfuscation'"
        "quantify, do not adjective"
      MASVS
        "MASVS-RESILIENCE-3 impede comprehension"
        "MASVS-CODE build hygiene"
    Measured here
      "12 classes to 4, dex 7384 B to 2920 B"
      "over-broad build equals no-rules build"
      "APK sizes identical - signing block padding"
      "unminified build leaked 7 .java filenames"
      "minified builds leaked none"
      "dead-code staging token shipped without tight rules"
      "Class.forName constant resolved and rewritten"
      "getDeclaredField NOT modelled - write the keep"
      "system app 1.3% renamed, commercial app 52.5%"
```

---

## The same material as a decision path

When you are handed an APK and asked "is this obfuscated, and does it matter?", this is the order.

```mermaid
flowchart TD
    A["APK in hand"] --> B["scripts/what-survived.py app.apk"]
    B --> C{"renamed % of the app's own package"}

    C -- "~0%" --> D{"original .java filenames present?"}
    D -- yes --> D1["minification is OFF"]
    D -- no  --> D2{"dead code removed?"}
    D2 -- yes --> D3["-dontobfuscate"]
    D2 -- "cannot tell" --> D4["over-broad -keep, or minify off.<br/>Say which you cannot distinguish"]

    C -- "partial" --> E["read the PACKAGE table"]
    E --> E1["an intact package among mangled ones<br/>= a scoped keep.<br/>That package is where they thought the value was"]

    C -- "high" --> F["list the survivors and bucket them"]
    F --> F1["manifest components — AGP's doing"]
    F --> F2["native-bound — the JNI rule"]
    F --> F3["library — consumer rules"]
    F --> F4["unexplained — the finding"]

    D1 --> G
    D3 --> G
    D4 --> G
    E1 --> G
    F4 --> G

    G{"does this app's threat model<br/>include a hostile user?"}
    G -- no --> H["one informational paragraph.<br/>Move on."]
    G -- yes --> I["write the finding:<br/>quote the rule, attach the numbers,<br/>state HARDENING ONLY, severity Low"]

    J["check the archive for<br/>mapping.txt / seeds.txt / *.pro"] --> K{"found?"}
    A --> J
    K -- yes --> L["separate finding.<br/>Severity proportional to what<br/>the obfuscation protected"]
    K -- no --> M["record 'checked and absent'"]

    style F4 fill:#f9d0d0
    style L fill:#f9d0d0
    style H fill:#e8f5e9
```

The two red boxes are the only places a real finding comes from. Everything else on this diagram is
description, and description at high severity is what gets a report dismissed.

---

## The rules-writing loop

The developer-side counterpart, which is what you recommend in remediation.

```mermaid
stateDiagram-v2
    direction TB
    [*] --> Empty
    Empty: Start from ZERO app rules
    Empty: not from the last project's file

    Empty --> Build
    Build: minifyEnabled true, build, install

    Build --> Exercise
    Exercise: exercise EVERY screen and flow
    Exercise: record each failure

    Exercise --> Classify
    Classify: ClassNotFoundException -> reflection
    Classify: NoSuchMethodException -> reflective member
    Classify: IllegalArgumentException from valueOf -> enum
    Classify: UnsatisfiedLinkError -> JNI
    Classify: LinkedTreeMap instead of a model -> Signature
    Classify: JSON keys became letters -> field names

    Classify --> Narrow
    Narrow: add the NARROWEST rule that fixes it
    Narrow: a class, a member, a signature
    Narrow: never a package wildcard
    Narrow: comment it - "delete this and X breaks"

    Narrow --> Exercise: still failing

    Narrow --> Review
    Review: read the file back
    Review: for each rule, can you write the sentence?
    Review: check seeds.txt shrank
    Review: run proguard-rules-audit.py --fail-on HIGH in CI

    Review --> [*]
```

Step "Review" is the one that gets skipped, and skipping it is why rules files only ever grow.
