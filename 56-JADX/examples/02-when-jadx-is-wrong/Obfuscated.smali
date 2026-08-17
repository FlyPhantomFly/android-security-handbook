# examples/02-when-jadx-is-wrong/Obfuscated.smali
#
# Chapter 56 (JADX) section 3.9 -- what --deobf actually does, and section 6.9 -- how a
# native declaration appears.
#
# Three identifiers, all called `a` or `b`, in a package called `a.b` -- the shape R8
# leaves behind. Run it twice:
#
#   jadx -q -d out-plain  Obfuscated.smali
#   jadx -q --deobf --deobf-cfg-file-mode ignore -d out-deobf Obfuscated.smali
#
# jadx 1.5.3, WITHOUT --deobf:
#
#   package a.b;
#   public class a {
#       /* renamed from: a, reason: collision with root package name */
#       private static String f0a;
#       public static String a(String str) { return str; }
#       public native int b();
#   }
#
# Note that jadx renamed the FIELD even with no flag: --rename-flags is on by default and
# jadx must legalise identifiers for the output to be self-consistent Java at all. It says
# so in a comment. Read the comments.
#
# jadx 1.5.3, WITH --deobf:
#
#   package p000a.p001b;
#   /* renamed from: a.b.a */
#   public class C0000a {
#       /* renamed from: a */
#       private static String f0a;
#       /* renamed from: a */
#       public static String m0a(String str) { return str; }
#       /* renamed from: b */
#       public native int m1b();
#   }
#
# The second is HARDER to read. Nothing was recovered. That is the point:
#
#   --deobf makes identifiers unique, valid and greppable. It does not recover meaning.
#
# What it buys you is real, though: `m0a` is unique app-wide where `a` is not, so
# cross-referencing and diffing between app versions become possible. Field `f0a` and
# method `m0a` no longer collide. And with --deobf-cfg-file the aliases persist in a
# .jobf file, so two versions of an app get the same names and a diff means something.
#
# Actual name recovery comes from elsewhere: --use-source-name-as-class-name-alias (if a
# SourceFile attribute survived), a recovered R8 mapping.txt, Kotlin's @Metadata, and you
# renaming things by hand as you understand them.
#
# Note also `public native int b();` -- a native method decompiles to a declaration with
# no body. That single line is the boundary between this chapter and 16-JNI / 57-Ghidra.
# See section 6.9.

.class public La/b/a;
.super Ljava/lang/Object;

.field private static a:Ljava/lang/String;

.method public static a(Ljava/lang/String;)Ljava/lang/String;
    .registers 2
    return-object p0
.end method

.method public native b()I
.end method
