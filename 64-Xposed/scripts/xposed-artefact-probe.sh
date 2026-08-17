#!/usr/bin/env bash
# scripts/xposed-artefact-probe.sh
#
# PURPOSE
#   Ask a device, from three different vantages, whether classic Xposed is
#   installed -- and show that the answers differ, that the difference is not
#   what most published detection lists assume, and that "absent" and
#   "forbidden" are not the same result even though File.exists() maps both to
#   false.
#
#   Classic Xposed left a small, specific set of artefacts on the SYSTEM
#   partition. That is the whole reason it is dead: nothing has been able to
#   write there since Verified Boot became mandatory. Those same paths are
#   still checked by shipping applications, so knowing exactly what they return
#   on a modern device is a deliverable and not a curiosity.
#
#   The script probes each path as ROOT, as SHELL (uid 2000), and -- the part
#   that matters -- as an APP UID via run-as, and prints the three answers side
#   by side with the errno-equivalent, not just a boolean.
#
# WHY THREE VANTAGES
#   This repository's most repeated finding, established independently by
#   chapters 37, 39, 48, 59 and 63: a detection probe verified from `adb shell`
#   has not been verified. `shell` sees 1,053 properties where an app sees 634;
#   /system/xbin/su is visible to shell and EACCES to an app. A signal that
#   fires only for shell reads as a working check, and a signal invisible to
#   shell reads as absent. Both errors are silent.
#
#   run-as is an imperfect proxy -- its SELinux domain is `runas_app`, not
#   `untrusted_app` -- and the script SAYS SO in its output rather than
#   quietly presenting it as an app result.
#
# USAGE
#   ./xposed-artefact-probe.sh [options]
#
#     --serial SERIAL     adb -s SERIAL. Pass this whenever more than one
#                         device is attached: a silent wrong-device attach is
#                         the worst kind, because every subsequent measurement
#                         is internally consistent and about the wrong target.
#     --as-package PKG    A DEBUGGABLE package to run the app-uid probes
#                         through. Without it the app column is skipped and
#                         says so rather than substituting shell results.
#     --no-root           Skip every probe that needs root.
#     --json              Machine-readable output.
#     -h, --help          This text.
#
# EXAMPLES
#   ./xposed-artefact-probe.sh --serial emulator-5554
#   ./xposed-artefact-probe.sh --serial emulator-5554 --as-package com.example.debuggable
#
# WHAT IT DOES NOT DO
#   It installs nothing, enables nothing, and writes nothing to the device.
#   Every command is a read. Posture enumeration frequently runs on devices you
#   have not been given permission to change.
#
# NOTE ON `su` -- two calling conventions, not compatible
#       su -c '<command>'      Magisk's su on most physical devices
#       su 0 <command>         the AOSP emulator's su
#   `su -c` on the emulator fails with `su: invalid uid/gid '-c'`, which reads
#   as "not rooted". This has nearly caused two chapters in this repository to
#   record a rooted device as unrooted. The script tries BOTH and reports which
#   worked.
#
#   Related and equally load-bearing: `adb shell su -c 'cmd'` is broken even on
#   a device whose su takes -c, because the OUTER shell strips the quotes and
#   su then eats the flag. Write `adb shell "su -c 'cmd'"`. This script always
#   uses the quoted form.
#
# EXECUTION STATUS
#   EXECUTED. Run to completion against an sdk_gphone16k_x86_64 AVD, Android 15
#   / API 35, rooted with Magisk 30.7, on 2026-08-16, with --as-package
#   pointing at a debuggable third-party app. Its output is what README
#   section 7.2 quotes.
#
# AUTHORISED TESTING ONLY.

set -u

SERIAL=""
AS_PKG=""
NO_ROOT=0
JSON=0

usage() { sed -n '2,70p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --serial)     SERIAL="${2:-}"; shift 2 ;;
        --as-package) AS_PKG="${2:-}"; shift 2 ;;
        --no-root)    NO_ROOT=1; shift ;;
        --json)       JSON=1; shift ;;
        -h|--help)    usage ;;
        *) printf '[FATAL] unknown option: %s (try --help)\n' "$1" >&2; exit 2 ;;
    esac
done

# MSYS mangles an absolute device path in an adb argument:
# /data/local/tmp becomes C:/Program Files/Git/data/local/tmp.
export MSYS_NO_PATHCONV=1

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

# `< /dev/null` is NOT optional and its absence produces a silent, wrong result.
# `adb shell` inherits stdin, so calling it inside a `... | while read` loop
# lets adb consume the REST OF THE LOOP'S INPUT. The loop then runs exactly
# once and exits cleanly, printing one row of a thirteen-row table with no
# error anywhere. Measured while writing this script: the artefact table
# printed a single line and looked like a device with nothing on it.
sh_cmd() { "${ADB[@]}" shell "$1" < /dev/null 2>&1 | tr -d '\r'; }

# ---------------------------------------------------------------------------
# Device identification. Always first, always recorded.
# ---------------------------------------------------------------------------
COUNT="$("${ADB[@]}" devices | grep -c 'device$' || true)"
if [ "$COUNT" -eq 0 ]; then
    echo "[FATAL] no device in state 'device'. Run: adb devices -l" >&2
    exit 2
fi
if [ "$COUNT" -gt 1 ] && [ -z "$SERIAL" ]; then
    echo "[FATAL] $COUNT devices attached and no --serial given. Refusing to guess." >&2
    "${ADB[@]}" devices -l >&2
    exit 2
fi

MODEL="$(sh_cmd 'getprop ro.product.model')"
SDKV="$(sh_cmd 'getprop ro.build.version.sdk')"
REL="$(sh_cmd 'getprop ro.build.version.release')"
ABI="$(sh_cmd 'getprop ro.product.cpu.abi')"

echo "======================================================================"
echo " CLASSIC XPOSED ARTEFACT PROBE"
echo "======================================================================"
echo " device : ${SERIAL:-<only attached>}"
echo " model  : $MODEL"
echo " release: Android $REL / API $SDKV   abi=$ABI"

# ---------------------------------------------------------------------------
# Root, and WHICH su convention.
# ---------------------------------------------------------------------------
SU_STYLE="none"
if [ "$NO_ROOT" = 0 ]; then
    if sh_cmd 'su 0 id' | grep -q 'uid=0'; then
        SU_STYLE="su0"
    elif sh_cmd "su -c 'id'" | grep -q 'uid=0'; then
        SU_STYLE="suc"
    fi
fi
echo " root   : $SU_STYLE  (su0 = 'su 0 cmd', suc = \"su -c 'cmd'\", none = unrooted or --no-root)"

as_root() {
    case "$SU_STYLE" in
        su0) sh_cmd "su 0 sh -c '$1'" ;;
        suc) sh_cmd "su -c '$1'" ;;
        *)   echo "(no root)" ;;
    esac
}

# ---------------------------------------------------------------------------
# The app vantage.
# ---------------------------------------------------------------------------
APP_OK=0
APP_CTX=""
if [ -n "$AS_PKG" ]; then
    APP_CTX="$(sh_cmd "run-as $AS_PKG id")"
    case "$APP_CTX" in
        uid=*) APP_OK=1 ;;
        *)
            echo " app    : run-as $AS_PKG FAILED -- $APP_CTX"
            echo "          run-as needs FLAG_DEBUGGABLE *and* an application uid."
            echo "          'package not an application' means it is a system app;"
            echo "          'package not debuggable' means the flag is off. They are"
            echo "          different refusals and reading the first as the second"
            echo "          loses a genuine finding."
            ;;
    esac
    [ "$APP_OK" = 1 ] && echo " app    : $APP_CTX"
else
    echo " app    : SKIPPED -- pass --as-package to measure from an app uid."
    echo "          Results below are then SHELL results and must be labelled as"
    echo "          such. A probe verified from adb shell has not been verified."
fi

as_app() {
    if [ "$APP_OK" = 1 ]; then
        sh_cmd "run-as $AS_PKG sh -c '$1'"
    else
        echo "(not measured)"
    fi
}

# ---------------------------------------------------------------------------
# The artefact list.
#
# Everything classic Xposed put on disk, plus the two paths people confuse it
# with. Each row carries what a hit WOULD have meant, so the output is
# self-documenting when it is pasted into a report.
# ---------------------------------------------------------------------------
PATHS="
/system/framework/XposedBridge.jar|classic Xposed's framework jar, added to the BOOT CLASS PATH by its modified app_process. LSPosed never creates it.
/system/xposed.prop|classic Xposed's version marker: version, arch, minsdk, maxsdk.
/system/lib64/libxposed_art.so|the ART-era native hooking engine that implemented hookMethodNative.
/system/lib/libxposed_art.so|the 32-bit build of the same.
/system/lib/libxposed_dalvik.so|the Dalvik-era engine, replaced when ART landed.
/system/bin/app_process|the binary classic Xposed REPLACED. Present on every device; presence proves nothing.
/system/bin/app_process32|32-bit variant, where the image ships one.
/system/bin/app_process64|64-bit variant. This is what the symlink usually points at.
/system/bin/app_process.orig|the backup a classic Xposed install left beside its replacement.
/data/data/de.robv.android.xposed.installer|the Xposed Installer's data directory.
/data/xposed|where the installer staged its files before flashing.
/data/adb/modules|the MODERN module store -- Magisk/Zygisk, therefore LSPosed. Not a classic artefact.
/data/adb/lspd|LSPosed's daemon directory. Included to show the errno difference.
"

echo
printf '%-46s %-10s %-10s %-10s\n' "PATH" "root" "shell" "app"
printf '%-46s %-10s %-10s %-10s\n' "---------------------------------------------" "----------" "----------" "----------"

# `ls -d` distinguishes the two failures that File.exists() cannot:
#   "No such file"      -> ENOENT, genuinely absent
#   "Permission denied" -> EACCES, present-or-absent, you are not allowed to know
classify() {
    case "$1" in
        *"No such file"*)      echo "ENOENT" ;;
        *"Permission denied"*) echo "EACCES" ;;
        *"not measured"*)      echo "-" ;;
        *"no root"*)           echo "-" ;;
        "")                    echo "?" ;;
        *)                     echo "PRESENT" ;;
    esac
}

printf '%s\n' "$PATHS" | while IFS='|' read -r p why; do
    [ -n "$p" ] || continue
    r="$(classify "$(as_root "ls -d $p 2>&1")")"
    s="$(classify "$(sh_cmd "ls -d $p 2>&1")")"
    a="$(classify "$(as_app "ls -d $p 2>&1")")"
    printf '%-46s %-10s %-10s %-10s\n' "$p" "$r" "$s" "$a"
done

echo
echo "----------------------------------------------------------------------"
echo " app_process, in detail -- the file the whole framework hung off"
echo "----------------------------------------------------------------------"
sh_cmd 'ls -l /system/bin/app_process /system/bin/app_process32 /system/bin/app_process64 2>&1'
echo
echo " mount state of /system (a classic install needed this WRITABLE):"
sh_cmd 'grep -E " /system | / " /proc/self/mounts' | sed 's/^/   /'
echo
echo " Verified Boot state:"
for k in ro.boot.verifiedbootstate ro.boot.flash.locked ro.boot.veritymode \
         ro.build.type ro.debuggable; do
    printf '   %-32s = %s\n' "$k" "$(sh_cmd "getprop $k")"
done

echo
echo "----------------------------------------------------------------------"
echo " Any process with an Xposed mapping? (classic Xposed was in EVERY one)"
echo "----------------------------------------------------------------------"
as_root 'for p in $(pidof zygote64 zygote system_server 2>/dev/null); do
             n=$(cat /proc/$p/cmdline 2>/dev/null | tr "\0" " ");
             c=$(grep -icE "xposed|lspd|lsposed|edxp|riru" /proc/$p/maps 2>/dev/null);
             echo "   pid=$p hits=$c  $n";
         done' | sed 's/^ *//;s/^/ /'

echo
cat <<'EOF'
----------------------------------------------------------------------
 HOW TO READ THIS
----------------------------------------------------------------------
 ENOENT vs EACCES is the whole point of the table.

   * java.io.File.exists() returns FALSE for both. An application that
     checks new File("/system/framework/XposedBridge.jar").exists() cannot
     distinguish "the framework is not installed" from "I am not allowed to
     look", and on the paths under /data/adb the answer is always the second.
   * A row that is ENOENT to ROOT is genuinely absent. That is the only
     column that can say so.
   * A row that is PRESENT to shell and EACCES to app is a check that works
     in your terminal and fails in the product. /system/xbin/su is the
     canonical example elsewhere in this repository.

 And the finding this whole script exists to support: on a modern image the
 classic-Xposed rows are ENOENT even to root, because /system is a read-only
 verified mount and nothing could have written them. An application still
 shipping those checks is running dead code. It is not a vulnerability; it is
 an integrity control that cannot fire, which is worth exactly one line in a
 report and no more.
EOF
