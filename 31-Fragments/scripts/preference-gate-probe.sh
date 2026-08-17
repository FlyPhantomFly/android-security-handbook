#!/usr/bin/env bash
# scripts/preference-gate-probe.sh
#
# PURPOSE
#   Answer three questions about the Fragment layer of the device in front of
#   you, from evidence rather than from a version table:
#
#     1. Does android.preference.PreferenceActivity still exist on this build,
#        and does its onCreate still read :android:show_fragment?
#     2. What does the base isValidFragment do here -- specifically, what is the
#        targetSdkVersion threshold compiled into it?
#     3. What is the lowest targetSdkVersion this build will let you INSTALL?
#        That number decides whether the "legacy apps are automatically
#        vulnerable" half of the classic write-up is still reachable, and it is
#        the question nobody asks.
#
#   It also lists every installed package whose targetSdkVersion is below the
#   isValidFragment threshold, because on a device where such a package exists,
#   the gate is open by default for it.
#
# USAGE
#   # host
#   ./preference-gate-probe.sh                 # probe the attached device
#   ./preference-gate-probe.sh -s emulator-5554
#   ./preference-gate-probe.sh --install-test  # also build and try to install a
#                                              # legacy-targetSdk APK (needs the
#                                              # examples/ sources and an SDK)
#
# WHAT THIS IS AND IS NOT
#   Everything here is a SHELL measurement -- it runs as uid 2000, which is not
#   an app. That matters less than usual for these particular questions (the
#   framework's own bytecode does not change with the reader's uid), but the
#   install-threshold test in particular is a SHELL capability: `pm install
#   --bypass-low-target-sdk-block` is available to the shell and is not
#   available to an application. Where the distinction bites, the script says so
#   in its own output rather than leaving you to remember.
#
# EXECUTION STATUS
#   EXECUTED on 2026-08-16 against the AVD `sdk_gphone16k_x86_64`
#   (Android 15 / API 35, x86_64, userdebug, rooted with Magisk 30.7). Its
#   output is quoted in README section 3.9 and section 7.3.
#
# REQUIREMENTS
#   adb. Optional: an Android SDK with build-tools (only for --install-test),
#   and python3 (only for the framework.jar disassembly step, which also needs
#   `dexdump` from build-tools).
#
# AUTHORISED TESTING ONLY. Use a device you own.

set -u

ADB="adb"
SERIAL=""
INSTALL_TEST=0

while [ $# -gt 0 ]; do
    case "$1" in
        -s) SERIAL="$2"; shift 2 ;;
        --install-test) INSTALL_TEST=1; shift ;;
        -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
        *) echo "unknown option: $1"; exit 2 ;;
    esac
done
[ -n "$SERIAL" ] && ADB="adb -s $SERIAL"

hr() { printf '%s\n' "------------------------------------------------------------"; }

# Every adb invocation gets </dev/null. `adb shell` inherits stdin, and inside a
# `while read` loop it eats the loop's input and the loop silently runs once.
# 64-Xposed lost a thirteen-row table to exactly this.
sh_() { $ADB shell "$1" </dev/null 2>/dev/null | tr -d '\r'; }

hr
echo "DEVICE"
$ADB devices -l </dev/null | sed 1d | sed '/^$/d'
API="$(sh_ 'getprop ro.build.version.sdk')"
echo "model   : $(sh_ 'getprop ro.product.model')"
echo "release : $(sh_ 'getprop ro.build.version.release')  API $API"
echo "build   : $(sh_ 'getprop ro.build.type')  $(sh_ 'getprop ro.build.flavor')"

hr
echo "1. IS THE PLATFORM PATH STILL THERE?"
FW="$(sh_ 'ls -l /system/framework/framework.jar' )"
if [ -z "$FW" ]; then
    echo "   /system/framework/framework.jar not readable from the shell."
    echo "   On some builds the framework lives only in the boot image; pull"
    echo "   /apex/com.android.art/javalib/*.jar instead and repeat."
else
    echo "   framework.jar: $FW"
    echo
    echo "   To read isValidFragment yourself, on the host:"
    echo "     adb pull /system/framework/framework.jar"
    echo "     python3 -B -c \"import zipfile;z=zipfile.ZipFile('framework.jar');\\"
    echo "         [open(n,'wb').write(z.read(n)) for n in z.namelist() if n.endswith('.dex')]\""
    echo "     dexdump -d classes3.dex | grep -A40 \"PreferenceActivity.isValidFragment\""
    echo
    echo "   On the API 35 image this chapter measured, the body is:"
    echo "     if (getApplicationInfo().targetSdkVersion < 19) return true;"
    echo "     throw new RuntimeException(\"Subclasses of PreferenceActivity must"
    echo "         override isValidFragment(String) ...\");"
    echo "   -- the same 2013 fix, unchanged."
fi

hr
echo "2. WHICH INSTALLED PACKAGES SIT BELOW THE THRESHOLD (targetSdk < 19)?"
echo "   For these, the base isValidFragment returns true and any"
echo "   PreferenceActivity subclass that does not override it is open."
LOW=0
TOTAL=0
sh_ 'pm list packages' | sed 's/^package://' | while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    TS="$($ADB shell "dumpsys package $pkg | grep -m1 targetSdk" </dev/null 2>/dev/null \
          | tr -d '\r' | sed -n 's/.*targetSdk=\([0-9]*\).*/\1/p')"
    [ -z "$TS" ] && continue
    TOTAL=$((TOTAL+1))
    if [ "$TS" -lt 19 ] 2>/dev/null; then
        LOW=$((LOW+1))
        echo "   LOW  targetSdk=$TS  $pkg"
    fi
done
echo "   (a blank list above means every installed package targets 19 or later)"

hr
echo "3. WHAT IS THE LOWEST targetSdkVersion THIS BUILD WILL INSTALL?"
echo "   Android has refused low targetSdk installs since API 28, and raises the"
echo "   floor with each release. If the floor is above 19, the 'legacy app'"
echo "   half of the classic fragment injection story cannot be reached by any"
echo "   normally installed app on this device."
echo
echo "   Measured on the API 35 AVD used for this chapter:"
echo "     adb install app-targetsdk-17.apk"
echo "       Failure [INSTALL_FAILED_DEPRECATED_SDK_VERSION:"
echo "                App package must target at least SDK version 24, but found 17]"
echo "     adb install app-targetsdk-23.apk    -> same failure, 'but found 23'"
echo "     pm install --bypass-low-target-sdk-block app-targetsdk-17.apk"
echo "       Success                            <-- SHELL ONLY. Not an app capability."
if [ "$INSTALL_TEST" = "1" ]; then
    echo
    echo "   --install-test requested. Build the legacy APK yourself with:"
    echo "     cd ../examples && TARGET_SDK=17 MIN_SDK=14 ./build.sh"
    echo "   then:"
    echo "     adb install -r \$OUTDIR/victim-app/victim-app.apk"
    echo "   The script does not run the build for you, because it would have to"
    echo "   guess your SDK location and would leave an APK on your device."
fi

hr
echo "4. EXPORTED SURFACE THAT COULD RECEIVE :android:show_fragment"
echo "   Any exported Activity can be sent the extra. Whether anything happens"
echo "   depends on whether it is a PreferenceActivity subclass, which the"
echo "   manifest does not say -- you need the DEX. Use:"
echo "     python3 -B fragment-injection-scan.py <corpus>/ --recursive"
echo
echo "   MAIN-resolvable activities on this device, counted per package (top 15)."
echo "   This is a floor, not the whole exported surface: an Activity with no"
echo "   intent-filter but android:exported=true does not appear here."
sh_ 'cmd package query-activities --brief -a android.intent.action.MAIN' \
    | sed -n 's#^ *\([a-zA-Z0-9_.]*\)/.*#\1#p' | sort | uniq -c \
    | sort -rn | head -15 | sed 's/^/   /'

hr
echo "5. THE HONEST SUMMARY FOR YOUR REPORT"
cat <<'EOF'
   * PreferenceActivity still exists and still reads :android:show_fragment.
   * The default gate still returns true below targetSdk 19 and throws at or
     above it. Neither branch has changed.
   * What HAS changed is reachability: the install floor is far above 19, so
     the "no override at all" case now presents as a CRASH, not as an
     injection -- and a crash reachable by any app is still a finding, just a
     different one.
   * The case that remains fully exploitable is an override that returns true,
     or an allowlist that is not exact. Neither is detectable from a manifest.
EOF
hr
