# examples/02-when-jadx-is-wrong/VariantV4.smali
#
# Chapter 56 (JADX) section 6.6 -- the narrowing experiment, sharpest variant.
#
# This is the same program as Accumulate.smali, written with the EXACT register allocation
# that javac --release 8 + d8 --release produce for the equivalent Java source (see the
# `original` method in Proof.java). Verified: `jadx -m fallback` renders this file and the
# compiler's own DEX IDENTICALLY --
#
#     public static int f(int[] r2) {
#             r0 = 0
#             r0 = r2[r0]     // Catch: java.lang.Exception -> L8
#             r1 = 1
#             r2 = r2[r1]     // Catch: java.lang.Exception -> L8
#             int r0 = r0 + r2
#             goto La
#         L8:
#             int r0 = r0 + 100
#         La:
#             return r0
#     }
#
# -- same registers, same catch range, same branch targets, same labels.
#
# And yet:
#
#   jadx on THIS file:                jadx on the javac + d8 build:
#     try {                             int i = 0;
#       return iArr[0] + iArr[1];       try { i = iArr[0]; return i + iArr[1]; }
#     } catch (Exception unused) {      catch (Exception unused) {
#       return 0 + 100;    <-- WRONG      return i + 100;    <-- correct
#     }                                 }
#
# For xs = {5} the first returns 100 and the second returns 105. Run Proof.java.
#
# Three further variants were tried and all three behaved like this one:
#   V1  accumulator written by three-address `add-int v0, v0, v1` instead of `add-int/2addr`
#   V2  `.registers 6`, second aget into v1
#   V3  handler with NO `move-exception` (matching d8's output, which discards the exception)
#
# So the trigger is not /2addr, not move-exception, and not register numbering. It lives
# somewhere the fallback instruction dump does not show, and this experiment did not find
# it. That is recorded rather than glossed over.
#
# CAVEAT TO STATE IF YOU REPORT THIS: these variants reach jadx through jadx's own
# smali-input assembler. A difference introduced by the assembler rather than by the
# decompiler has not been ruled out. The right destination is a minimal reproducer on
# https://github.com/skylot/jadx/issues -- not an assertion that the tool is broken.
#
# The operational conclusion does not depend on the cause:
#
#   jadx's correctness is a property of the SHAPE of the bytecode, not of the semantics of
#   the program -- and the Java gives you no way to tell which case you are in.

.class public LVariantV4;
.super Ljava/lang/Object;

.method public static f([I)I
    .registers 3
    const/4 v0, 0x0
:t
    aget v0, p0, v0
    const/4 v1, 0x1
    aget p0, p0, v1
    add-int/2addr v0, p0
:e
    goto :o
:h
    add-int/lit8 v0, v0, 0x64
:o
    return v0
    .catch Ljava/lang/Exception; {:t .. :e} :h
.end method
