# examples/PatchCookbook.smali
#
# The nine Smali patches you will actually make, each shown as BEFORE and AFTER,
# with the register accounting spelled out and the specific way each one goes
# wrong. README section 9.4 indexes them.
#
# HOW TO USE THIS FILE
#     It is a reference, not a class to assemble. Every recipe is a comment block
#     containing two listings. Copy the AFTER, adapt the register numbers to the
#     method you are actually editing, and re-check .registers/.locals.
#
# THE THREE RULES THAT GOVERN ALL NINE
#     1. Every register you name must exist. If you need a new one, raise
#        .locals (preferred) or .registers (and then fix every raw vN that
#        aliased a parameter).
#     2. The instruction family must match the type. A method returning
#        Ljava/lang/String; needs return-object, never return.
#     3. move-result* must stay glued to its invoke. Insert before the invoke or
#        after the move-result, never between them.
#
# Check your work before you rebuild:
#     python3 ../scripts/smali_frame.py <yourfile>.smali --check


# ===========================================================================
# 1. FORCE A BOOLEAN METHOD TO RETURN TRUE
# ===========================================================================
#
# The most common patch in existence: a root check, a licence check, an
# entitlement check.
#
# BEFORE
#     .method public isDeviceRooted()Z
#         .locals 2
#         const-string v0, "/system/xbin/su"
#         new-instance v1, Ljava/io/File;
#         invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
#         invoke-virtual {v1}, Ljava/io/File;->exists()Z
#         move-result v0
#         return v0
#     .end method
#
# AFTER
#     .method public isDeviceRooted()Z
#         .locals 1
#         const/4 v0, 0x0
#         return v0
#     .end method
#
# NOTE the direction. For a method NAMED isDeviceRooted you want FALSE, not
# true. Read the caller before you choose the constant -- "make it return true"
# is the reflex and it is wrong half the time.
#
# TRAP
#     If the original said .locals 0 you MUST raise it to at least 1, because v0
#     does not otherwise exist. The assembler catches this one, so it is cheap.
#
# TRAP
#     Deleting the body also deletes the new-instance/invoke-direct pair. That is
#     fine here. It would NOT be fine if something later in the method used v1.


# ===========================================================================
# 2. FORCE A BOOLEAN METHOD TO RETURN FALSE
# ===========================================================================
#
# AFTER
#     .method public hasValidLicence()Z
#         .locals 1
#         const/4 v0, 0x0
#         return v0
#     .end method
#
# const/4 encodes a 4-bit signed literal, so it covers -8..+7. That is enough for
# 0 and 1. For anything larger use const/16 (16-bit) or const (32-bit).


# ===========================================================================
# 3. NEUTER A VOID METHOD
# ===========================================================================
#
# For a method whose job is to report, exit, or enforce.
#
# BEFORE
#     .method private enforceIntegrity()V
#         .locals 3
#         invoke-direct {p0}, Lcom/example/Guard;->hash()[B
#         move-result-object v0
#         ...
#         invoke-static {}, Ljava/lang/System;->exit(I)V
#         return-void
#     .end method
#
# AFTER
#     .method private enforceIntegrity()V
#         .locals 0
#         return-void
#     .end method
#
# TRAP
#     Check what happens AFTER the call site. If the caller relies on a side
#     effect -- a field this method was supposed to set -- emptying it produces a
#     NullPointerException somewhere else entirely, and you will spend an hour
#     looking in the wrong place. When in doubt, keep the body and neuter only
#     the final decision.
#
# TRAP
#     If the method body sat inside a try/catch in the CALLER, and the caller's
#     catch block did the real work, removing the throw changes which path runs.


# ===========================================================================
# 4. INVERT A BRANCH
# ===========================================================================
#
# One character in the text, two bits on disk, and the easiest thing in the world
# to get backwards.
#
# BEFORE
#     invoke-virtual {p0}, Lcom/example/Guard;->isTampered()Z
#     move-result v0
#     if-eqz v0, :cond_normal          # branch WHEN v0 IS ZERO
#     invoke-static {}, Ljava/lang/System;->exit(I)V
#     :cond_normal
#
# AFTER
#     if-nez v0, :cond_normal          # branch when v0 is NON-zero
#
# READ IT LIKE THIS
#     The condition on the instruction is the condition under which the branch is
#     TAKEN. Everything immediately after the branch is the path where the
#     condition was FALSE. Java's `if (x) { A } else { B }` compiles to a test of
#     the OPPOSITE of x, so the Smali always looks inverted relative to the
#     source.
#
# TRAP
#     Confirm by running the app, never by re-reading the Smali. Reading it twice
#     the same wrong way is a well-documented human failure mode.


# ===========================================================================
# 5. SKIP A BLOCK WITH GOTO
# ===========================================================================
#
# Better than deleting, because it does not move any other instruction and
# therefore cannot disturb an exception table.
#
# BEFORE
#     invoke-direct {p0}, Lcom/example/App;->checkSignature()V
#     invoke-direct {p0}, Lcom/example/App;->checkDebugger()V
#     invoke-direct {p0}, Lcom/example/App;->startUi()V
#     return-void
#
# AFTER
#     goto :patch_skip
#     invoke-direct {p0}, Lcom/example/App;->checkSignature()V
#     invoke-direct {p0}, Lcom/example/App;->checkDebugger()V
#     :patch_skip
#     invoke-direct {p0}, Lcom/example/App;->startUi()V
#     return-void
#
# NOTE the label name. Use an obviously hand-written name like :patch_skip rather
# than imitating baksmali's :goto_N, so a later reader can see what you added.
#
# TRAP
#     Never jump INTO or OUT OF a try range. A branch that lands inside a
#     protected region from outside it, or leaves one mid-way, produces control
#     flow the verifier's exception analysis will not accept.
#
# ALTERNATIVE -- replace instructions with nop
#     nop
#     nop
#   Two nops occupy 2 code units, an invoke-virtual (35c) occupies 3. You cannot
#   pad an arbitrary instruction to the same size, and you do not need to: the
#   assembler recomputes every offset. nop-padding matters only when you are
#   patching RAW BYTES in a DEX, which is a different technique.


# ===========================================================================
# 6. OVERWRITE A CALL'S RETURN VALUE
# ===========================================================================
#
# The cleanest way to change what a call produced without touching the callee --
# useful when the callee is in a library you would rather not modify.
#
# BEFORE
#     invoke-static {v2}, Lcom/example/Api;->verifyToken(Ljava/lang/String;)Z
#     move-result v0
#     if-eqz v0, :cond_fail
#
# AFTER
#     invoke-static {v2}, Lcom/example/Api;->verifyToken(Ljava/lang/String;)Z
#     move-result v0
#     const/4 v0, 0x1              # <-- inserted AFTER move-result
#     if-eqz v0, :cond_fail
#
# TRAP
#     The insertion goes after move-result, never between the invoke and it. This
#     is THE rule, and breaking it is the number-one cause of a patched APK that
#     installs and then dies on one screen.
#
# TRAP
#     The call still runs. If verifyToken() makes a network request, throws, or
#     takes four seconds, all of that still happens. If you need it not to run,
#     patch the callee or goto over the call.


# ===========================================================================
# 7. INJECT A LOG LINE
# ===========================================================================
#
# BEFORE
#     .method private computeToken(Ljava/lang/String;)Ljava/lang/String;
#         .registers 4
#         invoke-static {p1}, Lcom/example/Crypto;->hmac(Ljava/lang/String;)Ljava/lang/String;
#         move-result-object v0
#         return-object v0
#     .end method
#
# AFTER
#     .method private computeToken(Ljava/lang/String;)Ljava/lang/String;
#         .registers 6
#         invoke-static {p1}, Lcom/example/Crypto;->hmac(Ljava/lang/String;)Ljava/lang/String;
#         move-result-object v0
#
#         const-string v1, "SMALIPATCH"
#         invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
#
#         return-object v0
#     .end method
#
# FOUR THINGS HAD TO BE RIGHT
#     1. .registers went 4 -> 6 so v1 exists (with headroom).
#     2. Raising .registers moved p1 from v3 to v5 -- harmless ONLY because the
#        body writes p1, not v3. This is why you use p names.
#     3. The insertion is after move-result-object.
#     4. No move-result after Log.d. It returns an int we do not want, and
#        discarding a return value by not collecting it is legal.
#
# CONVERTING NON-STRINGS
#     Log.d takes two Strings. Anything else must be converted first:
#         invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;
#         invoke-static {v0}, Ljava/lang/String;->valueOf(Z)Ljava/lang/String;
#         invoke-static {v0}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;
#         invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;
#         invoke-static {v0}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;
#     each followed by move-result-object into the register you will pass.
#
# WATCH IT
#     adb logcat -s SMALIPATCH:D


# ===========================================================================
# 8. REDIRECT A CALL TO YOUR OWN CLASS
# ===========================================================================
#
# When a small edit will not do, add a whole new class and point the call at it.
#
# BEFORE
#     invoke-virtual {v1, v2}, Lcom/example/Crypto;->encrypt([B)[B
#     move-result-object v3
#
# AFTER
#     invoke-static {v1, v2}, Lcom/patch/Hook;->encrypt(Lcom/example/Crypto;[B)[B
#     move-result-object v3
#
# NOTE the descriptor change. The original was invoke-VIRTUAL, so v1 was the
# receiver and did not appear in the descriptor. The replacement is
# invoke-STATIC, so the receiver becomes an explicit first parameter and MUST
# appear in the descriptor. Get this wrong and you get NoSuchMethodError at
# runtime, not a build failure.
#
# Then drop this file in as smali/com/patch/Hook.smali:
#
#     .class public Lcom/patch/Hook;
#     .super Ljava/lang/Object;
#
#     .method public static encrypt(Lcom/example/Crypto;[B)[B
#         .locals 2
#         const-string v0, "SMALIPATCH"
#         invoke-static {p1}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;
#         move-result-object v1
#         invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
#         invoke-virtual {p0, p1}, Lcom/example/Crypto;->encrypt([B)[B
#         move-result-object v0
#         return-object v0
#     .end method
#
# apktool picks up new .smali files under smali*/ automatically; there is nothing
# to register. This is the Smali equivalent of a Frida hook, and it works on an
# unrooted device with no tooling installed.
#
# TRAP
#     Put your class under smali/ (the first tree). Adding it to smali_classes3/
#     works too but multidex ordering is a build artefact and there is no reason
#     to depend on it.


# ===========================================================================
# 9. RETURN A CONSTANT STRING (OR NULL)
# ===========================================================================
#
# AFTER -- constant String
#     .method public getServerUrl()Ljava/lang/String;
#         .locals 1
#         const-string v0, "https://127.0.0.1:8080/"
#         return-object v0
#     .end method
#
# AFTER -- null
#     .method public getCachedToken()Ljava/lang/String;
#         .locals 1
#         const/4 v0, 0x0
#         return-object v0
#     .end method
#
# TRAP
#     return-object, NOT return. Using `return` on a reference is a VerifyError.
#     And note that null really is const/4 v0, 0x0 -- a null reference is the
#     zero value; the OPCODE, return-object, is what tells the verifier the
#     register holds a reference.
#
# OTHER RETURN TYPES
#     int / short / byte / char / float     const/4 v0, 0x0        + return v0
#     long / double                         const-wide/16 v0, 0x0  + return-wide v0
#                                           (occupies v0:v1 -- .locals 2)
#     void                                  return-void
#     array or object                       const/4 v0, 0x0        + return-object v0


# ===========================================================================
# AFTER ANY PATCH -- the rebuild pipeline, in this order
# ===========================================================================
#
#     apktool b work/ -o patched.apk
#     zipalign -p -f -v 4 patched.apk aligned.apk
#     apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android \
#         --out signed.apk aligned.apk
#     apksigner verify -v signed.apk
#     adb uninstall com.example.target
#     adb install signed.apk
#     adb logcat -c && adb logcat -s art:* AndroidRuntime:* SMALIPATCH:D
#
# ALIGN BEFORE SIGNING. v2+ signatures cover the whole file, so aligning
# afterwards invalidates them.
#
# UNINSTALL FIRST. You re-signed with a different key, so the OS considers this a
# different application and will refuse an in-place update.
#
# IF IT INSTALLS AND THEN CRASHES ON ONE SCREEN, that is the verifier, not the
# assembler. Read the rejection in logcat; it names the method and the offset.
