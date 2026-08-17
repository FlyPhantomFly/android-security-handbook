# examples/02-when-jadx-is-wrong/Irreducible.smali
#
# Chapter 56 (JADX) section 6.4 -- FAILURE MODE ONE: REFUSAL.
#
# Two methods that jadx cannot express as Java, for two different structural reasons.
# Feed this file straight to jadx; jadx bundles a Smali assembler, so no apktool,
# smali.jar or Android SDK is needed:
#
#   jadx -d out Irreducible.smali
#   jadx --show-bad-code -d out-bad Irreducible.smali
#   jadx -m simple      -d out-simple Irreducible.smali
#   jadx -m fallback    -d out-fb     Irreducible.smali
#
# See ./reproduce.sh, which runs all four and prints the differences.
# Captured output for jadx 1.5.3 is in jadx-output-irreducible.txt.
#
# The instruction set itself is chapter 14's subject, not this chapter's:
#   ../../../14-Dalvik/README.md

.class public Lcom/pentest/ch56/Irr;
.super Ljava/lang/Object;


# A loop with TWO entry points. Structured Java has no goto, so every control-flow graph
# javac or kotlinc can emit is REDUCIBLE -- every loop has exactly one entry. This one has
# two, so there is no Java program with this shape. jadx does not fail here because it is
# not clever enough; it fails because the target language cannot express the input.
#
# jadx 1.5.3 emits:
#   JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:8:0x000a -> B:4:0x0003)
#   ... and replaces the body with throw new UnsupportedOperationException.
#
# With --show-bad-code it instead prints:
#   public static int irreducible(int i, int i2) { int i3 = 0; }
# which assigns an unused local and FALLS OFF THE END WITHOUT RETURNING. That is worse
# than the default, because it looks like a method that does nothing.
.method public static irreducible(II)I
    .registers 6
    const/4 v0, 0x0
    if-eqz p0, :entry_b            # first entry into the loop body

:entry_a
    add-int/lit8 v0, v0, 0x1
    if-ge v0, p1, :done
    goto :entry_b

:entry_b                            # second entry into the same loop
    add-int/lit8 v0, v0, 0x2
    if-ge v0, p1, :done
    goto :entry_a

:done
    return v0
.end method


# An exception handler that jumps back INTO its own protected region. Java can express a
# retry loop, but not one whose back edge lands in the middle of the try block it came from.
#
# Worth running to see what jadx does with it: on jadx 1.5.3 this one does NOT refuse. It
# produces plausible-looking Java. Whether that Java is faithful is exactly the question
# Accumulate.smali is about -- and the point is that you cannot tell by looking.
.method public static overlapping(Ljava/lang/String;)I
    .registers 5
    const/4 v0, 0x0

:try_start
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v1
    add-int/2addr v0, v1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I
    move-result v2
    add-int/2addr v0, v2
:try_end
    goto :out

:handler
    move-exception v3
    add-int/lit8 v0, v0, 0x64
    goto :try_start                 # back into the protected region

:out
    return v0

    .catch Ljava/lang/Exception; {:try_start .. :try_end} :handler
.end method
