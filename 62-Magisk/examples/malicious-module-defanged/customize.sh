#!/system/bin/sh
#
# ============================================================================
#  LAB FIXTURE - DEFANGED - DO NOT INSTALL
#
#  This file is a teaching artefact for chapter 62 lab 04. It is written to
#  look like the install script of a trojanised Magisk module. Every hostile
#  command is passed to would(), which PRINTS its arguments and returns; it
#  never executes anything. There is no arming switch and no other code path.
#
#  In the wild, this header would not exist and the comments below would read
#  as ordinary developer chatter.
# ============================================================================

LAB_LOG=/data/local/tmp/DEFANGED-fixture.log

would() {
    echo "[DEFANGED] would have run: $*" >> "$LAB_LOG"
    return 0
}

ui_print "- Device Optimizer Pro v4.3"
ui_print "- Applying performance profile..."

# ---------------------------------------------------------------------------
# Behaviour 1: install a second application, silently.
#
# The cover story is a "companion app for the settings UI". A real module has
# no business installing anything: Magisk modules and Android applications are
# separate distribution channels, and a module that installs an APK has just
# bypassed the Play Store, the sideload warning and the user's consent in one
# line. The APK ships inside the module archive, under a directory name chosen
# to look like resources.
# ---------------------------------------------------------------------------
ui_print "- Installing companion service"
would pm install -r "$MODPATH/common/res/optimizer-companion.apk"

# ---------------------------------------------------------------------------
# Behaviour 2: grant that application runtime permissions with no prompt.
#
# `pm grant` as root bypasses the runtime permission dialog entirely. The user
# is never asked. Note the permissions chosen: they are the ones an SMS-stealing
# or 2FA-intercepting payload needs, and they have nothing whatever to do with
# battery life.
# ---------------------------------------------------------------------------
for p in android.permission.READ_SMS \
         android.permission.RECEIVE_SMS \
         android.permission.READ_CONTACTS \
         android.permission.READ_PHONE_STATE; do
    would pm grant com.optimizer.companion "$p"
done

# ---------------------------------------------------------------------------
# Behaviour 3: stage the boot payload outside the module directory.
#
# Copying executable content out of /data/adb/modules means that removing the
# module does not remove the payload. Removal is the user's only remediation,
# and this defeats it.
# ---------------------------------------------------------------------------
would cp "$MODPATH/common/res/opt.bin" /data/local/tmp/.opt
would chmod 0755 /data/local/tmp/.opt

# ---------------------------------------------------------------------------
# Normal-looking housekeeping, so the script reads like a real installer.
# ---------------------------------------------------------------------------
set_perm_recursive "$MODPATH" 0 0 0755 0644

ui_print "- Optimisation profile applied"
ui_print "- Reboot to activate"

echo "[DEFANGED] customize.sh completed - nothing was executed" >> "$LAB_LOG"
