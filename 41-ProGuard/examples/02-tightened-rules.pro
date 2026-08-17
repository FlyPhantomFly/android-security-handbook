# examples/02-tightened-rules.pro
#
# THE GOOD ONE. The same application, the same functionality, the same three
# genuine reflection requirements -- expressed as narrowly as the language
# allows.
#
# The discipline that produced it, in four steps, is the whole of chapter
# section 3.10:
#
#   1. Start from ZERO app-specific rules. Not from the last project's file.
#   2. Build, install, and exercise every screen. Write down each crash.
#   3. For each crash, add the NARROWEST rule that fixes it -- a class, a
#      member, a signature. Never a package wildcard.
#   4. Re-run the app. Repeat until clean. Then read the file back and ask of
#      every line: what breaks if I delete this?
#
# Step 4 is the one that gets skipped, and it is the one that keeps the file
# from growing forever.
#
# HOW TO USE IT
#   ./keeplab/build.sh                  # builds A, B and C; B uses this file
#   python3 -B ../scripts/proguard-rules-audit.py 02-tightened-rules.pro
#
# Every rule below carries the sentence "delete this and X breaks". If you
# cannot write that sentence for a rule in your own file, the rule is a guess.

# ==========================================================================
# 1. ENTRY POINTS
# ==========================================================================
# Delete this and: the launcher cannot start the app -- PackageManager looks
# for the literal string in the manifest and finds nothing.
#
# In a real AGP build you do NOT write this rule. AGP generates it from the
# merged manifest into
#   app/build/intermediates/aapt_proguard_file/<variant>/aapt_rules.txt
# and passes it to R8 alongside your file. It is written out here only because
# keeplab/build.sh drives R8 directly, with no AGP to generate it. Read your
# own project's aapt_rules.txt before you add a component keep by hand -- it is
# almost certainly already there.
-keep class com.pentest.ch41.MainActivity { <init>(...); }

# ==========================================================================
# 2. REFLECTION
# ==========================================================================
# Delete this and: under ProGuard, MainActivity's
# Class.forName("...ReflectionEntry") throws ClassNotFoundException, because
# nothing in the BYTECODE references the class -- only a string does -- and the
# shrinker reads bytecode edges, not strings.
#
# MEASURED CORRECTION, R8 8.6.2: deleting this rule does NOT break the fixture.
# R8 recognises the constant-string Class.forName idiom, resolves it at build
# time, replaces the call with `const-class La/a;`, and keeps the class (renamed
# to a.a) together with its constructor, its field and toString(). The app works
# and the string vanishes from the DEX. Reproduce it: delete these four lines,
# rerun keeplab/build.sh, and read the mapping.
#
# The rule stays anyway, and this is the discipline the chapter argues for:
# R8's reflection modelling is IDIOM MATCHING, not analysis. It stops without
# warning -- labs/ctf-vault shows the same forName resolution succeeding while
# a getDeclaredField("FIFTH") on the resolved class is NOT modelled, so the
# field is removed and the app throws NoSuchFieldException at runtime. A rule
# you did not need costs nothing; a rule you needed and skipped costs a crash.
#
# Note the member signature. Keeping the class alone is not enough in R8 full
# mode, which is the AGP 8 default: newInstance() needs the no-argument
# constructor kept explicitly. This is the single most common "it worked in
# compat mode" migration break.
-keep class com.pentest.ch41.ReflectionEntry {
    <init>();
}

# ==========================================================================
# 3. ENUMS USED BY NAME
# ==========================================================================
# Delete this and: Transaction.parseKind("REFUND", ...) throws
# IllegalArgumentException, because valueOf matches the constant's name and the
# constants were renamed to a, b, c.
#
# This is the canonical rule from Google's own proguard-android.txt. Note that
# it targets MEMBERS of enum classes -- it does not keep the enum class name,
# only the two methods the runtime resolves by name plus, implicitly, the
# constant fields those methods enumerate.
-keepclassmembers enum com.pentest.ch41.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ==========================================================================
# 4. NATIVE METHODS
# ==========================================================================
# Delete this and: a statically-bound JNI method fails to resolve at first
# call, with an UnsatisfiedLinkError naming a symbol that does not exist in the
# .so -- because the .so exports Java_com_pentest_ch41_LicenseValidator_
# nativeCheck and R8 renamed the Java side to a.a.b.
#
# `<methods>` here means "every method of a class that HAS a native method".
# The narrower and more correct form -- keep only the native ones -- is what
# the second rule does, and it is what you should prefer.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# ==========================================================================
# 5. SERIALISATION
# ==========================================================================
# Delete this and: a Transaction serialised by version 1.4 of the app cannot be
# read back by version 1.5, because field names are written into the stream and
# R8 assigned different ones on the second build.
#
# Scoped to the ONE class that is actually Serializable, not to `class *`.
# If you can move to a wire format with explicit names (protobuf, or GSON with
# @SerializedName on every field), delete this rule instead of narrowing it --
# the annotation carries the name so the field is free to be renamed.
-keepclassmembers class com.pentest.ch41.Transaction {
    private final java.lang.String currency;
    private final long amountMinor;
}

# ==========================================================================
# 6. ATTRIBUTES -- keep exactly what is read at runtime, nothing else
# ==========================================================================
# Delete Signature and: any generic type read reflectively (GSON's TypeToken is
# the usual victim) resolves to Object and deserialisation returns
# LinkedTreeMap instead of your model.
#
# Delete the annotation attributes and: @WireName is stripped from the DEX, so
# the runtime cannot read the wire names and the JSON keys silently become the
# obfuscated field names.
#
# InnerClasses and EnclosingMethod are needed for getSimpleName() and for
# anonymous-class reflection to behave.
-keepattributes Signature
-keepattributes RuntimeVisibleAnnotations,RuntimeVisibleParameterAnnotations
-keepattributes AnnotationDefault
-keepattributes InnerClasses,EnclosingMethod
-keepattributes Exceptions

# --------------------------------------------------------------------------
# The stack-trace pair, done properly
# --------------------------------------------------------------------------
# SourceFile and LineNumberTable are what make a stack trace resolvable. Keeping
# them alone would put the ORIGINAL .java filenames back in the DEX -- so the
# second line overwrites every filename with a single constant. The line
# numbers survive, the filenames do not, and mapping.txt turns the result back
# into a readable trace on your crash dashboard.
#
# This is the rule that developers reach for -dontobfuscate instead of.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# ==========================================================================
# 7. WHAT IS DELIBERATELY ABSENT
# ==========================================================================
# No -dontwarn. If R8 warns about a missing class, that warning is telling you
# a dependency is incomplete; silence it per-class, with a comment, or fix the
# dependency.
#
# No -dontobfuscate, -dontoptimize or -dontshrink. Turning any of the three off
# globally is a decision that should be argued for in a commit message, not
# inherited from a template.
#
# No rule for Analytics, LicenseValidator, Transaction's class name, or
# DeadCode. They do not need one, so they do not get one -- LicenseValidator
# and Transaction get renamed, and DeadCode is removed from the APK entirely.
