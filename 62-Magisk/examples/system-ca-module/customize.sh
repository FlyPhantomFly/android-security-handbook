#!/system/bin/sh
#
# customize.sh — runs at INSTALL time, inside the Magisk installer, as root.
#
# What runs here and what does not:
#   * This script executes once, when the module is installed. It does NOT run at
#     boot. Boot-time work goes in post-fs-data.sh or service.sh.
#   * Magisk sources util_functions.sh into this environment first, so ui_print,
#     set_perm, set_perm_recursive, abort, $MODPATH, $API and $ARCH are available
#     here and NOWHERE ELSE. None of them exist in service.sh.
#
# What this script does:
#   1. Removes placeholder files that belong to the repository, not to a device.
#   2. Refuses to install if no certificate is present, rather than installing a
#      module that silently does nothing.
#   3. Sets ownership and permission bits on the overlay. Magisk labels the files
#      for SELinux when it mounts them; it does not guess your intended mode.
#   4. Prints what it installed, so the installer log is evidence.
#
# What it does NOT do:
#   * It does not validate that the file is a CA certificate, or that its filename
#     is the correct subject hash. That check needs openssl and belongs on the host.
#     See this module's README.md.

CERTDIR="$MODPATH/system/etc/security/cacerts"

ui_print "----------------------------------------------------"
ui_print " Pentest System CA"
ui_print " AUTHORISED TESTING DEVICES ONLY."
ui_print " Every TLS connection on this device becomes"
ui_print " interceptable by whoever holds the matching key."
ui_print "----------------------------------------------------"

# 1. Repository placeholders must never reach a device's trust store.
rm -f "$CERTDIR"/.gitkeep "$CERTDIR"/*.md 2>/dev/null

# 2. Fail loudly rather than installing an empty module.
COUNT=0
for f in "$CERTDIR"/*; do
    [ -e "$f" ] || continue
    COUNT=$((COUNT + 1))
done

if [ "$COUNT" -eq 0 ]; then
    ui_print "! No certificate found in system/etc/security/cacerts/"
    ui_print "! Produce one on the host first:"
    ui_print "!   HASH=\$(openssl x509 -inform PEM -subject_hash_old -in ca.pem | head -1)"
    ui_print "!   cp ca.pem system/etc/security/cacerts/\${HASH}.0"
    abort "! Refusing to install a module that would do nothing."
fi

# 3. Ownership and modes. root:root, dirs 0755, files 0644 — the same as the
#    directory this overlays.
set_perm_recursive "$MODPATH/system" 0 0 0755 0644

# 4. Evidence.
ui_print "- Certificates installed by this module:"
for f in "$CERTDIR"/*; do
    [ -e "$f" ] || continue
    ui_print "    $(basename "$f")"
done

# 5. Version-specific honesty. On Android 14+ the runtime reads the Conscrypt
#    APEX trust store, not this path, so this module can install cleanly and
#    still intercept nothing. Say so at install time rather than letting the
#    user discover it during an engagement.
if [ -n "$API" ] && [ "$API" -ge 34 ]; then
    ui_print " "
    ui_print "! WARNING: API $API detected (Android 14+)."
    ui_print "! The system trust store is managed by the Conscrypt APEX at"
    ui_print "!   /apex/com.android.conscrypt/cacerts"
    ui_print "! An overlay on /system/etc/security/cacerts is NOT read by the"
    ui_print "! runtime on this version. This module will install and will"
    ui_print "! probably intercept nothing. Verify before you rely on it."
fi

ui_print "- Reboot to activate."
