# labs/ctf-vault/Vault.smali
#
# Chapter 56 (JADX) -- Lab 04, "The Honest Decompiler".
#
# There is exactly one flag in this class and it is of the form CTF{...}.
#
# Decompile it and read it:
#
#     jadx -d out Vault.smali
#     cat out/sources/com/pentest/ch56/ctf/Vault.java
#
# You need nothing but jadx. It bundles a Smali assembler, so this file is a complete,
# self-contained input -- no apktool, no smali.jar, no Android SDK, no device.
#
# The lab brief is ../lab-04-ctf-honest-decompiler.md. Read it before you start; it explains
# what you are being tested on, which is not "can you write a XOR loop".
#
# Do not read SOLUTION.md until you have a flag you believe in.

.class public Lcom/pentest/ch56/ctf/Vault;
.super Ljava/lang/Object;


.field public static final BANNER:Ljava/lang/String; = "CTF{read_the_java_and_stopped}"


.method public static seed()I
    .registers 6
    const/4 v0, 0x1
    new-array v1, v0, [I
    const/4 v2, 0x0
    const/16 v3, 0x35
    aput v3, v1, v2
    const/4 v0, 0x0

:try_start
    const/4 v2, 0x0
    aget v2, v1, v2
    add-int/2addr v0, v2
    const/4 v2, 0x1
    aget v2, v1, v2
    add-int/2addr v0, v2
:try_end
    goto :out

:handler
    move-exception v4
    add-int/lit8 v0, v0, 0xd

:out
    return v0

    .catch Ljava/lang/Exception; {:try_start .. :try_end} :handler
.end method


.method public static rounds(I)I
    .registers 4
    const/4 v0, 0x0
    const/16 v1, 0x7
    if-eqz p0, :entry_b

:entry_a
    add-int/lit8 v0, v0, 0x1
    if-ge v0, v1, :done
    goto :entry_b

:entry_b
    add-int/lit8 v0, v0, 0x2
    if-ge v0, v1, :done
    goto :entry_a

:done
    return v0
.end method


.method public static flag()Ljava/lang/String;
    .registers 12

    const/16 v5, 0x1c
    new-array v0, v5, [B
    fill-array-data v0, :enc_data

    invoke-static {}, Lcom/pentest/ch56/ctf/Vault;->seed()I
    move-result v1

    and-int/lit8 v6, v1, 0x1
    invoke-static {v6}, Lcom/pentest/ch56/ctf/Vault;->rounds(I)I
    move-result v2

    new-array v3, v5, [C
    const/4 v4, 0x0

:loop
    if-ge v4, v5, :loop_end
    add-int v6, v4, v2
    rem-int/2addr v6, v5
    aget-byte v7, v0, v6
    xor-int/2addr v7, v1
    int-to-char v7, v7
    aput-char v7, v3, v4
    add-int/lit8 v4, v4, 0x1
    goto :loop

:loop_end
    new-instance v8, Ljava/lang/String;
    invoke-direct {v8, v3}, Ljava/lang/String;-><init>([C)V
    return-object v8

    :enc_data
    .array-data 1
        0x27t
        0x30t
        0x1dt
        0x2et
        0x2bt
        0x27t
        0x31t
        0x3ft
        0x01t
        0x16t
        0x04t
        0x39t
        0x36t
        0x2at
        0x27t
        0x1dt
        0x20t
        0x3bt
        0x36t
        0x27t
        0x21t
        0x2dt
        0x26t
        0x27t
        0x1dt
        0x2ct
        0x27t
        0x34t
    .end array-data
.end method
