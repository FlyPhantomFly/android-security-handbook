.class public Lcom/artlab/dexdemo/PatchDemo;
.super Ljava/lang/Object;
.source "PatchDemo.java"

# ============================================================================
# PatchDemo.smali — the four patches you will actually make, annotated.
#
# WHAT THIS DEMONSTRATES
#   Every register-counting and instruction-ordering pitfall from
#   ../README.md sections 3.24 and 3.26, in the context of real patches.
#
#   Read the BEFORE and AFTER pairs together. The comments explain not just
#   what changed but why the naive version of the change breaks verification.
#
# HOW TO USE IT
#   1. Build any app containing an equivalent Java class.
#   2. apktool d app.apk -o work/
#   3. Edit work/smali/.../PatchDemo.smali following the patterns below.
#   4. apktool b work/ -o patched.apk
#      zipalign -p -f -v 4 patched.apk aligned.apk
#      apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android \
#                     --out signed.apk aligned.apk
#      adb install -r signed.apk
#
#   If the app INSTALLS but crashes when it reaches the patched class, you
#   broke verification, not the signature. Check:
#      adb logcat -s art
#   and look for a rejection naming the method. See README section 3.29.
# ============================================================================


# ----------------------------------------------------------------------------
# PATCH 1 — force a boolean method to return true
#
# The single most common patch in Android reverse engineering: defeating a
# check that returns false when something is wrong.
# ----------------------------------------------------------------------------

# ---- BEFORE ----
#
# .method public static isDeviceSecure(Landroid/content/Context;)Z
#     .registers 4
#     .param p0, "context"
#
#     invoke-static {p0}, Lcom/artlab/dexdemo/RootCheck;->isRooted(Landroid/content/Context;)Z
#     move-result v0
#
#     if-eqz v0, :not_rooted
#     const/4 v1, 0x0
#     return v1
#
#     :not_rooted
#     const/4 v1, 0x1
#     return v1
# .end method

# ---- AFTER ----
.method public static isDeviceSecure(Landroid/content/Context;)Z
    # We can safely REDUCE .registers because we now use fewer, but note that
    # ins_size is still 1 (the Context parameter), so p0 must still exist.
    # registers_size(2) - ins_size(1) = 1, so p0 == v1. v0 is our only local.
    .registers 2
    .param p0, "context"

    const/4 v0, 0x1          # format 11n: 4-bit signed literal, fits 0x1
    return v0                # format 11x
.end method

# WHY THIS WORKS
#   The entire body is replaced. The parameter register p0 is untouched — we
#   simply never read it. The verifier is satisfied because v0 is definitely
#   assigned before `return v0` reads it.
#
# THE MISTAKE TO AVOID
#   Writing `.registers 1`. That would make registers_size(1) - ins_size(1) = 0,
#   so p0 == v0, and `const/4 v0, 0x1` would overwrite the incoming Context
#   before... well, in this case nothing reads it, so it would actually still
#   work. But do it in a method that DOES use its parameter and you have a
#   silent, confusing bug. Always compute registers_size - ins_size.


# ----------------------------------------------------------------------------
# PATCH 2 — the move-result trap
#
# This is the mistake that produces "installs fine, crashes on that screen".
# ----------------------------------------------------------------------------

# ---- WRONG: logging inserted between invoke and move-result ----
#
# .method public static validate(Ljava/lang/String;)Z
#     .registers 4
#
#     invoke-static {p0}, Lcom/artlab/dexdemo/Validator;->check(Ljava/lang/String;)Z
#
#     # <-- ANY instruction here makes the DEX FAIL VERIFICATION.
#     const-string v2, "PatchDemo"
#     const-string v3, "validate called"
#     invoke-static {v2, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
#
#     move-result v0          # ERROR: no longer follows its invoke
#     return v0
# .end method
#
# The verifier requires move-result to IMMEDIATELY follow the invoke whose
# result it collects. The result lives in a distinguished slot valid for
# exactly one instruction. See README section 3.26.

# ---- RIGHT: log BEFORE the invoke ----
.method public static validate(Ljava/lang/String;)Z
    # registers_size(4) - ins_size(1) = 3, so p0 == v3.
    # v0, v1, v2 are locals.
    .registers 4
    .param p0, "input"

    const-string v1, "PatchDemo"
    const-string v2, "validate called"
    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    # NOTE: Log.d returns int. We do NOT collect it, which is legal — you may
    # omit move-result entirely if you do not want the value. What you may not
    # do is separate move-result from its invoke.

    invoke-static {p0}, Lcom/artlab/dexdemo/Validator;->check(Ljava/lang/String;)Z
    move-result v0           # immediately follows. Correct.

    return v0
.end method

# ---- ALSO RIGHT: log AFTER the move-result ----
.method public static validateAndLog(Ljava/lang/String;)Z
    .registers 4
    .param p0, "input"

    invoke-static {p0}, Lcom/artlab/dexdemo/Validator;->check(Ljava/lang/String;)Z
    move-result v0           # immediately follows the invoke. Correct.

    # Now that the result is safely in v0, insert whatever you like.
    const-string v1, "PatchDemo"
    invoke-static {v0}, Ljava/lang/String;->valueOf(Z)Ljava/lang/String;
    move-result-object v2    # again, immediately follows ITS invoke
    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    return v0
.end method


# ----------------------------------------------------------------------------
# PATCH 3 — wide values take TWO registers
#
# The second most common patching error.
# ----------------------------------------------------------------------------

.method public static getExpiry()J
    # We need to return a long. A long occupies TWO adjacent registers,
    # named by the lower number. So returning a long from v0 means v0 AND v1
    # are consumed, and .registers must be at least 2.
    .registers 2

    const-wide/16 v0, 0x0    # v0:v1 both written by this single instruction
    return-wide v0           # reads v0:v1
.end method

# THE MISTAKE TO AVOID
#   .registers 1 with const-wide v0 — v1 does not exist, verification fails.
#
# A METHOD SIGNATURE EXAMPLE
#   static void f(long a, int b)  with registers_size=4, ins_size=3:
#       p0 == v1, and 'a' occupies v1:v2
#       p1 == v3, holding 'b'
#   Note that p1 is v3, NOT v2 — the long swallowed a register. Miscount this
#   and you will read half a long as an int and get bizarre behaviour.


# ----------------------------------------------------------------------------
# PATCH 4 — neutralise a check without changing control flow
#
# Sometimes replacing the whole body is too blunt: the method has side effects
# you want to preserve. Patch only the decision.
# ----------------------------------------------------------------------------

# ---- BEFORE ----
#
#     invoke-static {}, Lcom/artlab/dexdemo/Integrity;->verify()Z
#     move-result v0
#     if-nez v0, :ok            # branch if verification PASSED
#     invoke-static {}, Lcom/artlab/dexdemo/Integrity;->reportTamper()V
#     :ok
#     ...

# ---- AFTER: invert the branch ----
#
#     invoke-static {}, Lcom/artlab/dexdemo/Integrity;->verify()Z
#     move-result v0
#     if-eqz v0, :ok            # <-- changed if-nez to if-eqz
#     invoke-static {}, Lcom/artlab/dexdemo/Integrity;->reportTamper()V
#     :ok
#     ...
#
# Or, cleaner, force the result:
#
#     invoke-static {}, Lcom/artlab/dexdemo/Integrity;->verify()Z
#     move-result v0
#     const/4 v0, 0x1           # <-- overwrite the result AFTER move-result
#     if-nez v0, :ok
#     ...
#
# The second form is usually better: the original method still runs (so any
# side effects it has still happen), you have not altered the branch structure,
# and the change is one obvious line. Note that `const/4 v0, 0x1` must come
# AFTER `move-result v0`, not between it and the invoke.


# ----------------------------------------------------------------------------
# REFERENCE — the register model, restated
#
#   registers_size   total registers in the frame
#   ins_size         how many, AT THE TOP, hold incoming arguments
#   first parameter register = registers_size - ins_size
#
#   .registers N     declares registers_size = N        (you do the arithmetic)
#   .locals N        declares locals only               (assembler computes the rest)
#
#   Prefer .locals — it is harder to get wrong, because adding a local does not
#   silently shift every p alias. Never mix .registers and .locals in one method.
#
#   Instance method: p0 == this
#   Static method:   p0 == first declared parameter
#   long / double:   occupies TWO adjacent registers, named by the lower
#
#   4-bit register fields (formats 11n, 12x, 22c, 35c) can only address v0-v15.
#   If the assembler rejects a register, use the /from16 variant or move the
#   value down into a low register first.
# ----------------------------------------------------------------------------
