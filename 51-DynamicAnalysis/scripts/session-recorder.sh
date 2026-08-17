#!/usr/bin/env bash
#
# session-recorder.sh -- bracket an EXERCISE WINDOW with two device snapshots
#                        and report what CHANGED.
#
# WHAT IT DOES
#   Dynamic analysis produces a river of output -- logcat scrolls, dumpsys is
#   ten thousand lines, the filesystem is a tree. Almost none of it is about
#   your app, and almost none of it changed. The signal is the DELTA: what was
#   different after you exercised the app that was not different before.
#
#   This script makes that delta a first-class artefact.
#
#     BEFORE   snapshot 01..09 below into <evidence>/before/
#     EXERCISE you drive the app (or --exec runs a command for you)
#     AFTER    the same nine snapshots into <evidence>/after/
#     REPORT   a single readable diff of what moved, into <evidence>/DELTA.md
#
#   The nine channels, in the order the report prints them:
#
#     01 IDENTITY    package version, uid, codePath, install source, flags
#     02 GRANTS      every runtime permission and its granted= state
#     03 PROCESS     pid, process state, oom_adj, whether it restarted
#     04 PRIVATE FS  every file under /data/data/<pkg> with size, mtime, md5
#     05 EXTERNAL FS /sdcard/Android/data/<pkg> and /sdcard/Android/media/<pkg>
#     06 RECEIVERS   the app's live registerReceiver() actions, from AMS
#     07 SERVICES    the app's running services and bound clients
#     08 NETWORK     device interface counters, and per-uid rows where present
#     09 LOGCAT      every line emitted during the window, filtered to the app
#
#   Channel 04 is the one that needs privilege, and it is the one this script
#   works hardest to obtain WITHOUT root -- see MODES below.
#
# MODES -- how channel 04 is obtained, and what each mode costs you
#   run-as   The app is debuggable and is not a system app. `adb shell run-as`
#            gives you a shell with the app's own uid and SELinux context. Full
#            read of the private data directory, no root. This is the mode the
#            chapter's worked example uses.
#   root     `su` is available. Full read of any app's private directory.
#   blind    Neither. Channel 04 is SKIPPED and the report says so, in place,
#            rather than printing an empty section that reads like "nothing
#            changed". Channels 01, 02, 03, 05, 06, 07, 08 and 09 all still
#            work, and between them they still catch a great deal.
#   The mode is auto-detected and printed. Force it with --mode.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - Whether anything that changed is a vulnerability. Every line of DELTA.md
#     is an OBSERVATION. A file appearing is not a finding; a file appearing
#     that contains a session token, readable by a party who should not have
#     it, is the beginning of one. Severity needs reachability and an asset,
#     and this script knows neither.
#   - Anything about code paths you did not exercise. This is the whole
#     limitation of dynamic analysis and no script removes it. A clean DELTA.md
#     means "nothing changed on the path I drove", never "the app does not do
#     that". Run scripts/coverage-reporter.py alongside this, so that the
#     report carries what you covered as well as what you saw.
#   - What happened INSIDE the process. No hooks are installed. Method calls,
#     reflection targets, decrypted buffers and in-memory secrets are all
#     invisible here. That is 53-Frida's job; this script is deliberately
#     instrumentation-free so that it works on the many devices where Frida
#     does not.
#   - The CONTENT of network traffic. Channel 08 counts bytes. Bytes are enough
#     to prove that a request happened during a window and enough to correlate
#     with a proxy log; they are not enough to say what was sent. Put a proxy
#     in front of the device for that -- see README section 3.5.
#   - Whether a change was caused by YOUR exercise. A device is a busy place.
#     Two snapshots of an idle device differ. Take a control run with
#     --exec 'true' and subtract; the report prints the window length so you
#     can judge.
#   - Anything at all about an app that is not installed, or a user other than
#     user 0.
#
# HOW TO RUN
#   # host -- the normal case: snapshot, prompt you to drive the app, snapshot
#   bash session-recorder.sh --package com.example.target --out ./evidence/s01
#
#   # host -- unattended: run a fixed exercise between the snapshots
#   bash session-recorder.sh -p com.example.target -o ./ev/s02 \
#        --exec 'adb shell monkey -p com.example.target -c android.intent.category.LAUNCHER 1'
#
#   # host -- unattended: just wait N seconds between the snapshots
#   bash session-recorder.sh -p com.example.target -o ./ev/s03 --wait 60
#
#   # host -- a CONTROL run: measure how much an idle device drifts
#   bash session-recorder.sh -p com.example.target -o ./ev/control --wait 60
#
#   # host -- re-print the report from an existing evidence directory
#   bash session-recorder.sh --report-only --out ./ev/s01
#
# REQUIREMENTS
#   adb on PATH, with exactly one device attached (or pass --serial).
#   A POSIX shell with sed, awk, sort, comm, diff. Git Bash on Windows is fine.
#   No root, no frida-server, no Python, nothing installed on the device.
#
# RELATED
#   ../README.md section 3.3        the baseline, and why it is stage two
#   ../README.md section 3.6        correlation -- what to do with a delta
#   ../README.md section 5.4        the known-value storage sweep
#   ./coverage-reporter.py          what you exercised, which this does not know
#   ../../77-UsefulCommands/scripts/session.sh
#                                   opens a session; this one closes a window
#   ../../29-BroadcastReceivers/scripts/receiver-surface.py
#                                   the whole-device receiver view; channel 06
#                                   is the single-app slice of it
#
# AUTHORISED TESTING ONLY. Only run this against applications you own or have
# written permission to test. On a shared or daily-driver device this script is
# read-only by design: it starts nothing, installs nothing, broadcasts nothing
# and deletes nothing unless you pass --exec a command that does.

set -uo pipefail

VERSION="1.0"

PKG=""
OUTDIR=""
SERIAL=""
MODE="auto"
WAIT=0
EXEC_CMD=""
REPORT_ONLY=0
QUIET=0
MD5=1

say()  { printf '%s\n' "$*" >&2; }
sub()  { printf '  %s\n' "$*" >&2; }
die()  { printf 'session-recorder: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,110p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Argument parsing. Hand-rolled rather than getopts, because getopts does not
# do long options portably and every flag here reads better long.
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)      usage 0 ;;
        -p|--package)   PKG="${2:-}";    shift 2 ;;
        -o|--out)       OUTDIR="${2:-}"; shift 2 ;;
        -s|--serial)    SERIAL="${2:-}"; shift 2 ;;
        --mode)         MODE="${2:-}";   shift 2 ;;
        --wait)         WAIT="${2:-}";   shift 2 ;;
        --exec)         EXEC_CMD="${2:-}"; shift 2 ;;
        --report-only)  REPORT_ONLY=1;   shift ;;
        --no-md5)       MD5=0;           shift ;;
        -q|--quiet)     QUIET=1;         shift ;;
        --version)      echo "session-recorder.sh $VERSION"; exit 0 ;;
        -*)             say "unknown option: $1"; usage 1 ;;
        *)              say "unexpected argument: $1"; usage 1 ;;
    esac
done

[ -n "$OUTDIR" ] || die "give --out <directory>"
if [ "$REPORT_ONLY" -eq 0 ]; then
    [ -n "$PKG" ] || die "give --package <applicationId>"
fi
case "$MODE" in auto|run-as|root|blind) ;; *) die "--mode must be auto, run-as, root or blind" ;; esac

ADB="adb"
[ -n "$SERIAL" ] && ADB="adb -s $SERIAL"

# A single place that runs one command on the device. `adb shell` does NOT
# preserve your host shell's quoting: it joins its arguments with spaces and
# hands the result to the device's /system/bin/sh. So the remote command must
# arrive as ONE argument, already quoted the way the DEVICE will read it.
# 09-Android-App-Internals lost two root sections to exactly this.
sh_dev() { $ADB shell "$1" 2>/dev/null; }

# ---------------------------------------------------------------------------
# Device identity. Recorded in every evidence directory, because a claim
# without a device is not a measurement. Two physical phones were used across
# this repository -- a rooted Redmi M2101K6P on Android 11 / API 30 with
# frida-server, and an unrooted i9000S on Android 13 / API 33 -- and they were
# swapped mid-session without warning. They differ in capability, not merely in
# version, so the serial and the props recorded below are part of the evidence
# rather than decoration.
# ---------------------------------------------------------------------------
record_device() {
    local out="$1"
    mkdir -p "$out"
    {
        echo "# device identity, recorded $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "serial            $($ADB get-serialno 2>/dev/null)"
        echo "model             $(sh_dev 'getprop ro.product.model')"
        echo "manufacturer      $(sh_dev 'getprop ro.product.manufacturer')"
        echo "release           $(sh_dev 'getprop ro.build.version.release')"
        echo "sdk               $(sh_dev 'getprop ro.build.version.sdk')"
        echo "security_patch    $(sh_dev 'getprop ro.build.version.security_patch')"
        echo "fingerprint       $(sh_dev 'getprop ro.build.fingerprint')"
        echo "abi               $(sh_dev 'getprop ro.product.cpu.abi')"
        echo "ro.debuggable     $(sh_dev 'getprop ro.debuggable')"
        echo "selinux           $(sh_dev 'getenforce')"
        echo "device_locked     $(sh_dev 'dumpsys trust' | grep -o 'deviceLocked=[01]' | head -1)"
        echo "shell_uid         $(sh_dev 'id -u')"
        echo "recorder_version  $VERSION"
    } > "$out/device.txt"
}

# ---------------------------------------------------------------------------
# Mode detection for channel 04.
#
# `run-as` has TWO preconditions and the error messages distinguish them, which
# is worth knowing because the folklore rule is only half right:
#   "package not debuggable: <pkg>"      -- FLAG_DEBUGGABLE is not set
#   "package not an application: <pkg>"  -- it IS debuggable but its uid is a
#                                          system uid (< 10000), which run-as
#                                          refuses regardless of the flag
# So "the app is debuggable" is necessary and not sufficient. Measured on the
# test device against three packages; see README section 3.4.
# ---------------------------------------------------------------------------
# Which `su` argument convention this device wants. Set by detect_mode().
# Magisk's su takes `su -c <command>`; an AOSP emulator's su takes a uid, and
# rejects -c with `su: invalid uid/gid '-c'` -- which reads exactly like "not
# rooted". Probing with one form and then executing with the other silently
# produces a blind run on a device that is in fact rooted, so both are tried
# here and the winner is remembered.
ROOT_FORM=""

detect_mode() {
    if [ "$MODE" != "auto" ]; then echo "$MODE"; return; fi
    local r
    r="$($ADB shell "run-as $PKG id" 2>&1)"
    case "$r" in
        *uid=*) echo "run-as"; return ;;
    esac
    r="$($ADB shell 'su -c id' 2>&1)"
    case "$r" in
        *uid=0*) echo "root"; return ;;
    esac
    r="$($ADB shell 'su 0 id' 2>&1)"
    case "$r" in
        *uid=0*) echo "root"; return ;;
    esac
    echo "blind"
}

# detect_mode() runs in a command substitution, so it cannot export anything.
# Work out the su convention separately, in this shell, once RUNMODE is known.
detect_root_form() {
    ROOT_FORM=""
    [ "$RUNMODE" = "root" ] || return 0
    case "$($ADB shell 'su -c id' 2>&1)" in
        *uid=0*) ROOT_FORM="-c"; return 0 ;;
    esac
    case "$($ADB shell 'su 0 id' 2>&1)" in
        *uid=0*) ROOT_FORM="0";  return 0 ;;
    esac
}

MODE_REASON=""
explain_mode() {
    case "$1" in
        run-as) MODE_REASON="the package is debuggable and has an app uid, so run-as gives a shell with its identity" ;;
        root)   MODE_REASON="su returned uid 0" ;;
        blind)  MODE_REASON="$($ADB shell "run-as $PKG id" 2>&1 | head -1)" ;;
    esac
}

# Run one command as the app: through run-as, through su, or not at all.
#
# The argument must be a bare argv line with NO quotes and NO shell
# metacharacters. That constraint is deliberate and it is not fussiness.
# `adb shell` does not preserve quoting: it joins its arguments with spaces and
# hands the string to the device's /system/bin/sh, so a nested
# `run-as PKG sh -c 'stat -c "%s %Y"'` arrives with its quotes already eaten
# and silently produces nothing. This cost chapter 09 two whole root sections.
# Passing a quote-free argv and letting run-as exec the binary directly removes
# the entire class of bug -- which is why the stat format below is
# comma-separated rather than space-separated.
as_app() {
    case "$RUNMODE" in
        run-as) $ADB shell "run-as $PKG $1" 2>/dev/null ;;
        root)   if [ "$ROOT_FORM" = "-c" ]; then
                    $ADB shell "su -c '$1'"  2>/dev/null
                else
                    $ADB shell "su 0 $1"     2>/dev/null
                fi ;;
        blind)  return 0 ;;
    esac
}

# ---------------------------------------------------------------------------
# The nine channels. Each writes exactly one file, sorted, so that `diff`
# between two snapshots is meaningful and stable. Anything with a timestamp,
# a counter or an object address in it gets normalised here rather than in the
# report, because a diff full of churn is a diff nobody reads.
# ---------------------------------------------------------------------------
snapshot() {
    local dir="$1" tag="$2"
    mkdir -p "$dir"
    [ "$QUIET" -eq 1 ] || sub "snapshot [$tag] -> $dir"

    # 01 IDENTITY -----------------------------------------------------------
    sh_dev "dumpsys package $PKG" \
      | grep -E 'versionName=|versionCode=|userId=|codePath=|firstInstallTime=|lastUpdateTime=|installerPackageName=|^ *flags=|^ *privateFlags=|targetSdk=|primaryCpuAbi=' \
      | sed 's/^[[:space:]]*//' | sort -u > "$dir/01-identity.txt"

    # 02 GRANTS -------------------------------------------------------------
    # Both the install-time list and the runtime grant state. The runtime rows
    # are the interesting ones: a permission can be requested, listed, and not
    # granted, and a dynamic pass is exactly how you learn WHEN it flipped.
    sh_dev "dumpsys package $PKG" \
      | grep -E '^[[:space:]]+(android\.permission|com\.[a-z0-9_.]+\.permission)[^:]*: granted=|^[[:space:]]+android\.permission\.[A-Z_]+$' \
      | sed 's/^[[:space:]]*//' | sed 's/, flags=\[.*\]//' | sort -u > "$dir/02-grants.txt"

    # 03 PROCESS ------------------------------------------------------------
    {
        local pid; pid="$(sh_dev "pidof $PKG" | tr -d '\r' | awk '{print $1}')"
        echo "pid ${pid:-(no process -- the app is not running)}"
        sh_dev "dumpsys activity processes" \
          | grep -F "$PKG" \
          | grep -oE '(ProcessRecord\{[^}]*\}|curProcState=[0-9]+|adj=[A-Za-z0-9_+-]+|oom: max=[0-9]+)' \
          | sed 's/ProcessRecord{[0-9a-f]* /ProcessRecord{/' | sort -u
    } > "$dir/03-process.txt"

    # 04 PRIVATE FS ---------------------------------------------------------
    # size, mtime and (optionally) md5 for every regular file. md5 is what
    # catches a file REWRITTEN with the same length, which happens constantly
    # with preference XML and is invisible to size alone.
    if [ "$RUNMODE" = "blind" ]; then
        echo "# SKIPPED: no run-as and no root. $MODE_REASON" > "$dir/04-privatefs.txt"
    else
        as_app "find /data/data/$PKG -type f -exec stat -c%s,%Y,%n {} +" \
          | tr -d '\r' | grep -F ",/data/data/$PKG" > "$dir/04-privatefs.stat"
        : > "$dir/04-privatefs.md5"
        if [ "$MD5" -eq 1 ]; then
            as_app "find /data/data/$PKG -type f -exec md5sum {} +" \
              | tr -d '\r' | grep -F "/data/data/$PKG" > "$dir/04-privatefs.md5"
        fi
        # One tab-separated record per file: path <TAB> size <TAB> md5-or-mtime.
        # md5 replaces mtime as the third field when it is available, because a
        # preferences file rewritten with identical content bumps mtime and is
        # not a change worth a paragraph, while a file rewritten to the same
        # LENGTH with different content is exactly the change you are hunting.
        awk -v pre="/data/data/$PKG/" '
            function short(p) { sub("^" pre, "", p); return p }
            FNR==NR { if (NF>=2) { h=$1; $2=short($2); md5[$2]=h } ; next }
            {
                n = split($0, f, ",")
                if (n < 3) next
                sz = f[1]; mt = f[2]
                path = f[3]; for (i=4; i<=n; i++) path = path "," f[i]
                key = short(path)
                printf "%s\t%s\t%s\n", key, sz, (key in md5 ? md5[key] : "mtime:" mt)
            }
        ' "$dir/04-privatefs.md5" "$dir/04-privatefs.stat" | sort > "$dir/04-privatefs.txt"
        rm -f "$dir/04-privatefs.stat" "$dir/04-privatefs.md5"
    fi

    # 05 EXTERNAL FS --------------------------------------------------------
    # Shell (uid 2000) can read these without any privilege at all, which is
    # exactly why they matter: anything an app writes here is outside the
    # sandbox boundary people assume protects it.
    {
        for d in "/sdcard/Android/data/$PKG" "/sdcard/Android/media/$PKG" "/sdcard/Android/obb/$PKG"; do
            sh_dev "find $d -type f -exec stat -c%s,%Y,%n {} +"
        done
    } | tr -d '\r' | grep -F "/$PKG" | sort > "$dir/05-externalfs.txt"

    # 06 RECEIVERS ----------------------------------------------------------
    # Every action this app has registered at RUNTIME. Nothing in the APK
    # says any of this; see README section 1.3 and chapter 29.
    # AMS prints one block per ReceiverList. The owning process is named on the
    # ReceiverList line itself and again on the `app=` line one line down, and
    # which of the two carries the package depends on the build -- so match on
    # either, and stop matching at the next block. Everything printed here was
    # created by a registerReceiver() call and appears in no manifest anywhere.
    sh_dev "dumpsys activity broadcasts" \
      | awk -v pkg="$PKG" '
          /ReceiverList\{/       { inblock = (index($0, pkg) > 0) }
          /^[[:space:]]+app=/    { if (index($0, pkg) > 0) inblock = 1 }
          inblock && /Action: /  { gsub(/^[[:space:]]+/,""); print }
        ' | sort -u > "$dir/06-receivers.txt"

    # 07 SERVICES -----------------------------------------------------------
    sh_dev "dumpsys activity services $PKG" \
      | grep -E 'ServiceRecord\{|app=|created=|startRequested=|Client ' \
      | sed 's/ServiceRecord{[0-9a-f]* /ServiceRecord{/' \
      | sed 's/^[[:space:]]*//' | sort -u > "$dir/07-services.txt"

    # 08 NETWORK ------------------------------------------------------------
    # Device-wide interface counters always work. Per-uid rows exist on some
    # builds and not others; /proc/net/xt_qtaguid/stats was removed after
    # Android 9 and is absent on the test device. The report says which of the
    # two it had, rather than silently printing nothing.
    local appuid
    appuid="$(grep -m1 -oE 'userId=[0-9]+' "$dir/01-identity.txt" | cut -d= -f2)"
    {
        sh_dev "cat /proc/net/dev" | tr -d '\r' \
          | awk 'NR>2 {gsub(/:/," "); if ($2+0 > 0 || $10+0 > 0) print "iface", $1, $2, $10}'
        if [ -n "$appuid" ]; then
            sh_dev "dumpsys netstats --full --uid" | tr -d '\r' \
              | grep -F "uid=$appuid " | sed 's/^[[:space:]]*/uid /' | head -40
        fi
    } > "$dir/08-network.txt"
}

# ---------------------------------------------------------------------------
# diff helpers. `comm` needs sorted input and gives clean added/removed sets;
# `diff` is used only where the CONTENT of a line changes (channel 04).
# ---------------------------------------------------------------------------
added()   { comm -13 "$1" "$2" 2>/dev/null; }
removed() { comm -23 "$1" "$2" 2>/dev/null; }

emit_set_section() {
    local title="$1" before="$2" after="$3" empty_note="$4"
    local a r
    a="$(added   "$before" "$after")"
    r="$(removed "$before" "$after")"
    echo ""
    echo "### $title"
    echo ""
    if [ -z "$a" ] && [ -z "$r" ]; then
        echo "No change. $empty_note"
        return
    fi
    if [ -n "$a" ]; then
        echo "**Appeared during the window:**"
        echo ""
        echo '```'
        printf '%s\n' "$a"
        echo '```'
    fi
    if [ -n "$r" ]; then
        echo ""
        echo "**Gone by the end of the window:**"
        echo ""
        echo '```'
        printf '%s\n' "$r"
        echo '```'
    fi
}

# Channel 08 is counters, not a set. Every interface counter moves on a live
# device, so a set difference prints every interface twice and says nothing.
# What you want is the arithmetic: which interface moved, and by how much.
emit_net_section() {
    local before="$1" after="$2"
    echo ""
    echo "### 08 Network counters"
    echo ""
    local moved
    moved="$(awk '
        FNR==NR { if ($1=="iface") { rx[$2]=$3; tx[$2]=$4 } ; next }
        $1=="iface" {
            drx = $3 - (($2 in rx) ? rx[$2] : $3)
            dtx = $4 - (($2 in tx) ? tx[$2] : $4)
            if (drx != 0 || dtx != 0)
                printf "  %-12s  rx +%-12d  tx +%d\n", $2, drx, dtx
        }' "$before" "$after")"
    if [ -z "$moved" ]; then
        echo "No interface counter moved. On a live device that usually means the two"
        echo "snapshots were seconds apart, not that the device was silent."
    else
        echo "Device-wide interface counters, in bytes:"
        echo ""
        echo '```'
        printf '%s\n' "$moved"
        echo '```'
        echo ""
        echo "**These are device-wide, not per-app.** They prove that traffic happened during"
        echo "the window; they do not prove your app caused it, and they say nothing about"
        echo "content. \`/proc/net/xt_qtaguid/stats\` -- the classic per-uid source -- was"
        echo "removed after Android 9 and does not exist on API 33. For attribution and for"
        echo "content, put a proxy in front of the device: README section 3.5."
    fi
    local ub ua
    ub="$(grep -c '^uid ' "$before" 2>/dev/null || echo 0)"
    ua="$(grep -c '^uid ' "$after"  2>/dev/null || echo 0)"
    if [ "$ub" = "0" ] && [ "$ua" = "0" ]; then
        echo ""
        echo "No per-uid rows were available from \`dumpsys netstats --full --uid\` for this"
        echo "package on this build. Recorded as a gap, not as zero traffic."
    fi
}

# Channel 04 needs three buckets, not two, because a file whose CONTENT
# changed is the most interesting case and set difference alone reports it as
# one removal plus one addition.
emit_fs_section() {
    local title="$1" before="$2" after="$3"
    echo ""
    echo "### $title"
    echo ""
    if head -1 "$before" 2>/dev/null | grep -q '^# SKIPPED'; then
        echo "**Not captured.** $(head -1 "$before" | sed 's/^# SKIPPED: //')"
        echo ""
        echo "This is a gap in the evidence, not an absence of change. Say so in the report."
        return
    fi
    local bp ap created deleted modified
    bp="$(mktemp)"; ap="$(mktemp)"
    cut -f1 "$before" | sort > "$bp"
    cut -f1 "$after"  | sort > "$ap"
    created="$(comm -13 "$bp" "$ap")"
    deleted="$(comm -23 "$bp" "$ap")"
    modified="$(join -t"$(printf '\t')" -j1 -o 0,1.2,1.3,2.2,2.3 \
                 <(sort -t"$(printf '\t')" -k1,1 "$before") \
                 <(sort -t"$(printf '\t')" -k1,1 "$after") 2>/dev/null \
               | awk -F'\t' '$2!=$4 || $3!=$5 {printf "%s\n    size  %s -> %s bytes\n    ident %s -> %s\n",$1,$2,$4,$3,$5}')"
    rm -f "$bp" "$ap"

    if [ -z "$created" ] && [ -z "$deleted" ] && [ -z "$modified" ]; then
        echo "No file under the private data directory was created, deleted or rewritten."
        echo "That is a real negative result and it is bounded by the window length."
        return
    fi
    [ -n "$created" ]  && { echo "**Created:**";  echo; echo '```'; printf '%s\n' "$created";  echo '```'; echo; }
    [ -n "$deleted" ]  && { echo "**Deleted:**";  echo; echo '```'; printf '%s\n' "$deleted";  echo '```'; echo; }
    [ -n "$modified" ] && { echo "**Rewritten (size or content identity moved):**"; echo; echo '```'; printf '%s\n' "$modified"; echo '```'; echo; }
    echo "Read a created or rewritten file before you rate it. A 4-byte file is"
    echo "not a credential store, and a 380-byte preferences XML is often six"
    echo "device-configuration strings. Section 5.4 of the README is the sweep."
}

# ---------------------------------------------------------------------------
# The report.
# ---------------------------------------------------------------------------
build_report() {
    local B="$OUTDIR/before" A="$OUTDIR/after" R="$OUTDIR/DELTA.md"
    local pkg_ver window
    pkg_ver="$(grep -m1 versionName "$B/01-identity.txt" 2>/dev/null)"
    window="$(cat "$OUTDIR/window.txt" 2>/dev/null || echo 'unknown')"

    {
        echo "# Session delta -- \`$PKG\`"
        echo ""
        echo "Produced by \`session-recorder.sh $VERSION\`. Everything below is an"
        echo "**observation**, bounded by the exercise window. Nothing below is a finding."
        echo ""
        echo "| | |"
        echo "|---|---|"
        echo "| Package | \`$PKG\` |"
        echo "| Version | \`${pkg_ver:-unknown}\` |"
        echo "| Exercise window | $window |"
        echo "| Private-FS mode | \`$RUNMODE\` -- $MODE_REASON |"
        echo "| Device | $(grep -m1 '^model' "$OUTDIR/before/device.txt" | awk '{print $2}') / API $(grep -m1 '^sdk' "$OUTDIR/before/device.txt" | awk '{print $2}') |"
        echo ""
        echo "---"
        echo ""
        echo "## What changed"

        emit_set_section "01 Identity"    "$B/01-identity.txt"   "$A/01-identity.txt" \
            "The package was not updated, reinstalled or moved during the window."
        emit_set_section "02 Permission grants" "$B/02-grants.txt" "$A/02-grants.txt" \
            "No runtime permission was granted or revoked during the window."
        emit_set_section "03 Process"     "$B/03-process.txt"    "$A/03-process.txt" \
            "The process neither started, died nor changed state band."
        emit_fs_section  "04 Private filesystem" "$B/04-privatefs.txt" "$A/04-privatefs.txt"
        emit_set_section "05 External storage" "$B/05-externalfs.txt" "$A/05-externalfs.txt" \
            "The app wrote nothing to its external directories during the window."
        emit_set_section "06 Runtime-registered receivers" "$B/06-receivers.txt" "$A/06-receivers.txt" \
            "The app's runtime broadcast surface was identical at both ends of the window. Note that a receiver registered AND unregistered inside the window is invisible to a two-snapshot method -- see the caveat below."
        emit_set_section "07 Services"    "$B/07-services.txt"   "$A/07-services.txt" \
            "No service of this app started, stopped or gained a client."
        emit_net_section "$B/08-network.txt" "$A/08-network.txt"

        echo ""
        echo "### 09 Logcat during the window"
        echo ""
        if [ -s "$OUTDIR/09-logcat.txt" ]; then
            local n
            n="$(wc -l < "$OUTDIR/09-logcat.txt" | tr -d ' ')"
            echo "$n line(s) captured, in \`09-logcat.txt\`. The lines most worth reading first:"
            echo ""
            echo '```'
            # Not `... | head -30 || echo "(no line matched...)"`. This script
            # sets pipefail, so once grep matches more than 30 lines head closes
            # the pipe, grep dies of SIGPIPE with status 141, and the "no line
            # matched" message would print directly beneath thirty matching
            # lines. Decide on the content, not on the exit status.
            local interesting
            interesting="$(grep -inE 'exception|error|fail|token|secret|password|key=|http://|https://|Bearer |\.db|shared_prefs' \
                 "$OUTDIR/09-logcat.txt" | head -30)"
            if [ -n "$interesting" ]; then
                printf '%s\n' "$interesting"
            else
                echo "(no line matched the interest filter)"
            fi
            echo '```'
            echo ""
            echo "Anything an app logs is readable by \`adb logcat\` with no root and by any"
            echo "app holding \`READ_LOGS\` on builds that still grant it. Treat a credential"
            echo "here as a finding about the log, not about the credential store."
        else
            echo "No log lines were attributed to this app during the window."
            echo ""
            echo "Two innocent causes before you conclude the app is quiet: the app runs in a"
            echo "process whose name differs from the package, and the ring buffer wrapped."
            echo "Check \`adb logcat -g\` -- on the test device \`main\` is a 256 KiB ring."
        fi

        echo ""
        echo "---"
        echo ""
        echo "## How to read this, and what it does not say"
        echo ""
        echo "1. **A two-snapshot method is blind to anything that returns to its starting"
        echo "   state.** A receiver registered in \`onResume\` and unregistered in \`onPause\`"
        echo "   is present in neither snapshot. A temp file written and deleted is invisible."
        echo "   For those, snapshot more often or install a hook -- see 53-Frida."
        echo "2. **A device is busy.** Some of the rows above will belong to the platform, not"
        echo "   to your exercise. Take a control run of the same length with the app idle and"
        echo "   subtract it before you attribute anything."
        echo "3. **Coverage is not recorded here.** This report says what changed, not what you"
        echo "   touched. Run \`coverage-reporter.py\` over the same window and attach both."
        echo "4. **Severity is not in this file and cannot be.** A created file becomes a"
        echo "   finding only when you have read it, established who else can reach it, and"
        echo "   named the asset. See 80-Appendix for the rubric."
        echo ""
        echo "Evidence directory: \`$OUTDIR\`"
    } > "$R"

    say ""
    say "report written: $R"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
if [ "$REPORT_ONLY" -eq 1 ]; then
    [ -d "$OUTDIR/before" ] || die "no snapshots in $OUTDIR"
    PKG="$(cat "$OUTDIR/package.txt" 2>/dev/null)"
    RUNMODE="$(cat "$OUTDIR/mode.txt" 2>/dev/null || echo blind)"
    explain_mode "$RUNMODE"
    build_report
    exit 0
fi

$ADB get-state >/dev/null 2>&1 || die "no device (or more than one -- pass --serial)"
sh_dev "pm path $PKG" | grep -q '^package:' || die "package not installed: $PKG"

mkdir -p "$OUTDIR"
printf '%s' "$PKG" > "$OUTDIR/package.txt"

RUNMODE="$(detect_mode)"
detect_root_form
explain_mode "$RUNMODE"
printf '%s' "$RUNMODE" > "$OUTDIR/mode.txt"

say "session-recorder $VERSION"
sub "package     $PKG"
sub "private-fs  $RUNMODE  ($MODE_REASON)"
sub "evidence    $OUTDIR"

record_device "$OUTDIR/before"
mkdir -p "$OUTDIR/after"
cp "$OUTDIR/before/device.txt" "$OUTDIR/after/device.txt" 2>/dev/null || :

# Mark the log position. `logcat -T` with a timestamp is more reliable than
# `-c`, which clears buffers you may not own and is a mutation of shared state
# on somebody's daily-driver phone.
LOG_START="$(sh_dev "date '+%m-%d %H:%M:%S.000'" | tr -d '\r')"
printf '%s' "$LOG_START" > "$OUTDIR/logstart.txt"

snapshot "$OUTDIR/before" "before"
T0="$(date +%s)"

# ---- the exercise window --------------------------------------------------
if [ -n "$EXEC_CMD" ]; then
    say ""
    say "exercising: $EXEC_CMD"
    ( eval "$EXEC_CMD" ) >"$OUTDIR/exercise.log" 2>&1 || sub "(exercise command returned non-zero -- recorded, not fatal)"
elif [ "$WAIT" -gt 0 ] 2>/dev/null; then
    say ""
    say "waiting ${WAIT}s -- drive the app now"
    sleep "$WAIT"
else
    say ""
    say "Drive the app now. Press Enter here when the exercise is finished."
    read -r _ || :
fi
T1="$(date +%s)"
printf '%s seconds\n' "$(( T1 - T0 ))" > "$OUTDIR/window.txt"

snapshot "$OUTDIR/after" "after"

# ---- logcat for the window ------------------------------------------------
APP_PID="$(sh_dev "pidof $PKG" | tr -d '\r' | awk '{print $1}')"
if [ -n "$APP_PID" ]; then
    $ADB logcat -d -T "$LOG_START" --pid="$APP_PID" 2>/dev/null | tr -d '\r' > "$OUTDIR/09-logcat.txt"
fi
# --pid misses everything the app logged before it was assigned this pid, and
# everything the SYSTEM logged about it. Both matter, so add a text filter.
$ADB logcat -d -T "$LOG_START" 2>/dev/null | tr -d '\r' | grep -F "$PKG" >> "$OUTDIR/09-logcat.txt" 2>/dev/null || :
sort -u -o "$OUTDIR/09-logcat.txt" "$OUTDIR/09-logcat.txt" 2>/dev/null || :

build_report
