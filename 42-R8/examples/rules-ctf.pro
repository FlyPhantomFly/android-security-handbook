# CTF rules: a realistic release configuration that nonetheless leaks three ways.
#
# Nothing here is contrived. Every directive below appears verbatim in real
# release builds; the leaks are consequences of ordinary choices, which is the
# point of the exercise.

# The application entry point, as AGP would keep a manifest-declared component.
-keep class com.pentest.ch42.ctf.CtfEntryPoint {
    public static void main(java.lang.String[]);
}

# Arrives via a dependency's consumer-rules.pro in real apps. This is why
# kotlin.Metadata survives in the wild at all -- the app author never asks for it.
-keepattributes RuntimeVisibleAnnotations
-keep class kotlin.Metadata { *; }

# "These specific classes are reached reflectively -- by a JSON mapper, a DI
# container or a serialiser -- so they must keep all their members. I do not
# care what they are called." The standard, and correct, narrow pattern.
-keep,allowobfuscation class com.pentest.ch42.ctf.Guard** { *; }
-keep,allowobfuscation class com.pentest.ch42.ctf.SegmentCarrier { *; }
-keep,allowobfuscation class com.pentest.ch42.ctf.VaultGuardian { *; }
-keep,allowobfuscation class com.pentest.ch42.ctf.HolderOrdering { *; }

# Looked up reflectively BY NAME, so it cannot be renamed. Note the ABSENCE of
# `allowobfuscation` here -- that single difference is what exempts the class
# name from obfuscation, and it is the most common real-world leak of all.
-keep class com.pentest.ch42.ctf.SegmentThreeIsK33PRUL3 { *; }

-dontwarn kotlin.**
-dontwarn org.jetbrains.annotations.**
-dontwarn java.lang.invoke.**
