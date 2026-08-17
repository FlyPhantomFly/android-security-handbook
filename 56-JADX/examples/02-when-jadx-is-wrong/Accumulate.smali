# examples/02-when-jadx-is-wrong/Accumulate.smali
#
# Chapter 56 (JADX) section 6.6 -- FAILURE MODE THREE: SILENCE.
#
# The dangerous one. jadx 1.5.3 decompiles the method below into clean, idiomatic,
# compiling Java, with NO warning of any kind -- and the Java returns a different value
# from the bytecode on the exception path.
#
#   bytecode, for xs = {5}:  105
#   jadx's Java, same input: 100
#
# Proof.java in this directory runs both readings on the JVM and prints both numbers.
#
# Run it:
#   jadx -q -d out Accumulate.smali
#   javac -d . Proof.java && java -cp . Proof
#
# or just ./reproduce.sh
#
# The instruction set is chapter 14's subject: ../../../14-Dalvik/README.md

.class public Lcom/pentest/ch56/Acc;
.super Ljava/lang/Object;


# acc starts at 0.
# Each aget can throw ArrayIndexOutOfBoundsException, which is an Exception, so the
# handler catches it. The handler adds 100 to WHATEVER acc HOLDS AT THAT MOMENT.
#
# Trace it for xs = {5}:
#   v0 = 0
#   aget xs[0]  -> 5,  v0 = 0 + 5 = 5
#   aget xs[1]  -> THROWS
#   handler     -> v0 = 5 + 100 = 105
#   return 105
#
# jadx 1.5.3 prints:
#
#   public static int accumulate(int[] iArr) {
#       try {
#           return 0 + iArr[0] + iArr[1];
#       } catch (Exception e) {
#           return 0 + 100;
#       }
#   }
#
# which returns 100. The partially-accumulated value that was live on the exception edge
# has been folded away into an expression. No JADX WARN comment is emitted.
#
# The tell, if you are looking for one: the leading "0 +" in both returns. A human writes
# `return iArr[0] + iArr[1]` and `return 100`. A leading constant in a folded expression
# inside a try block is the residue of an accumulator, and an accumulator inside a try is
# exactly where an exception edge can observe a partial value.
.method public static accumulate([I)I
    .registers 6
    const/4 v0, 0x0              # acc = 0

:try_start
    const/4 v1, 0x0
    aget v1, p0, v1              # xs[0]   -- may throw
    add-int/2addr v0, v1         # acc += xs[0]   <-- observable on the exception edge
    const/4 v2, 0x1
    aget v2, p0, v2              # xs[1]   -- may throw
    add-int/2addr v0, v2         # acc += xs[1]
:try_end
    goto :out

:handler
    move-exception v3
    add-int/lit8 v0, v0, 0x64    # acc += 100

:out
    return v0

    .catch Ljava/lang/Exception; {:try_start .. :try_end} :handler
.end method
