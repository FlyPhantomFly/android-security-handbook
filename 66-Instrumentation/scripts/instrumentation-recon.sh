#!/usr/bin/env bash
# scripts/instrumentation-recon.sh
#
# PURPOSE
#   The five-minute reconnaissance pass for the test-instrumentation attack
#   surface on a device you are assessing. It answers, in order:
#
#     1. What instrumentations are ALREADY registered, and what do they target?
#        Each row is a package that can run code inside another package's
#        process, today, with no further work from you.
#     2. Which of those targets are third-party rather than platform?
#     3. Is this build debuggable (ro.debuggable), which relaxes several checks?
#     4. Which installed packages are themselves debuggable?
#     5. Which are marked testOnly, i.e. shipped from a test pipeline?
#     6. Can this shell start an instrumentation at all, and as which identity?
#
#   Nothing here writes to the device, installs anything, or force-stops a
#   process. It is read-only reconnaissance; running the instrumentation is a
#   separate, louder step and belongs in a separate command.
#
# USAGE
#   # host -- against the only attached device
#   ./instrumentation-recon.sh
#
#   # host -- against a specific device
#   ./instrumentation-recon.sh -s emulator-5554
#
#   # host -- include the (slower) per-package flag sweep
#   ./instrumentation-recon.sh --deep
#
# WAS THIS SCRIPT EXECUTED?
#   YES. Run on 2026-08-16 against the AVD sdk_gphone16k_x86_64 (Android 15 /
#   API 35, userdebug, 247 packages). Its measured output is quoted in README.md
#   section 7.2. The headline result was that a stock Android 15 GMS image
#   registers ZERO instrumentations -- a useful baseline, because it means every
#   row you ever see on a real device was put there by somebody.
#
# READ THIS BEFORE TRUSTING ANY ROW
#   `pm list instrumentation` reads the PackageManager's parsed manifests. It
#   therefore finds DECLARED instrumentations and is completely blind to test
#   code that shipped inside an ordinary APK with no <instrumentation> component.
#   That residue is common and is worth more to a reviewer than the declared
#   kind. Use scripts/instrumentation-surface.py for it. The two checks are
#   complementary, not redundant, and this chapter measured a real example that
#   only the second one finds.
#
# AUTHORISED TESTING ONLY. Run against devices and applications you own or are
# contracted to assess.

set -u

ADB="adb"
DEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        -s) ADB="adb -s ${2:-}"; shift 2 ;;
        --deep) DEEP=1; shift ;;
        -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1"; exit 2 ;;
    esac
done

# adb mangles absolute remote paths under MSYS.
export MSYS_NO_PATHCONV=1

# Every adb invocation inside a loop gets < /dev/null. `adb shell` inherits
# stdin, so an unredirected call inside a `while read` loop eats the loop's own
# input and the loop exits after one iteration -- silently, looking exactly like
# a device with nothing on it. Chapter 64 lost a thirteen-row table to this.
sh_() { $ADB shell "$@" < /dev/null 2>&1 | tr -d '\r'; }

hr() { printf '%s\n' "-----------------------------------------------------------------"; }

# --------------------------------------------------------------------------- #
echo "== device =="
$ADB devices -l | sed -n '2,$p'
printf '  model          %s\n' "$(sh_ getprop ro.product.model)"
printf '  release / sdk  %s / %s\n' "$(sh_ getprop ro.build.version.release)" \
                                    "$(sh_ getprop ro.build.version.sdk)"
printf '  build type     %s\n' "$(sh_ getprop ro.build.type)"
printf '  ro.debuggable  %s\n' "$(sh_ getprop ro.debuggable)"
printf '  ro.secure      %s\n' "$(sh_ getprop ro.secure)"
printf '  shell identity %s\n' "$(sh_ id)"
hr

# --------------------------------------------------------------------------- #
echo "== registered instrumentations =="
INSTR="$(sh_ pm list instrumentation -f)"
if [ -z "$INSTR" ]; then
    echo "  (none)"
    echo
    echo "  A device with zero rows is the normal state of a stock image, and it"
    echo "  is a useful baseline rather than a dead end: any row you see later"
    echo "  was installed by somebody, and is worth a paragraph in the report."
else
    printf '%s\n' "$INSTR" | sed 's/^/  /'
fi
hr

# --------------------------------------------------------------------------- #
echo "== instrumentation targets, resolved =="
if [ -n "$INSTR" ]; then
    printf '%s\n' "$INSTR" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        comp="$(printf '%s' "$line" | sed -n 's/.*=\([^ ]*\) (target=.*/\1/p')"
        tgt="$(printf '%s' "$line" | sed -n 's/.*(target=\([^)]*\)).*/\1/p')"
        [ -z "$tgt" ] && continue
        tpath="$(sh_ "pm path $tgt" | head -1)"
        case "$tpath" in
            *"/data/app/"*) origin="third-party or updated" ;;
            "")             origin="TARGET NOT INSTALLED" ;;
            *)              origin="platform image" ;;
        esac
        printf '  runner  %s\n' "$comp"
        printf '  target  %-46s %s\n' "$tgt" "$origin"
        printf '\n'
    done
else
    echo "  (nothing to resolve)"
fi
hr

# --------------------------------------------------------------------------- #
echo "== can this shell start an instrumentation? =="
echo "  am instrument's own defaults assume a shell caller. Two of them require"
echo "  permissions an app uid does not hold, which is why an app-uid attempt"
echo "  fails with a message about users or hidden API rather than about"
echo "  instrumentation. See README section 3.10."
printf '  am supports:   %s\n' \
    "$(sh_ 'am help' | grep -c 'no-hidden-api-checks') option(s) named no-hidden-api-checks"
hr

# --------------------------------------------------------------------------- #
echo "== debuggable and testOnly packages =="
if [ "$DEEP" -eq 1 ]; then
    echo "  (deep sweep: one dumpsys per package, this takes a minute)"
    sh_ 'pm list packages' | sed 's/^package://' | while IFS= read -r pkg; do
        [ -z "$pkg" ] && continue
        flags="$($ADB shell "dumpsys package $pkg" < /dev/null 2>/dev/null \
                 | tr -d '\r' | grep -m1 -E '^[[:space:]]+flags=')"
        case "$flags" in
            *DEBUGGABLE*|*TEST_ONLY*)
                printf '  %-52s %s\n' "$pkg" "$(printf '%s' "$flags" | sed 's/^ *//')" ;;
        esac
    done
    echo "  (end of sweep)"
else
    echo "  skipped. Re-run with --deep to sweep every package's flags."
    echo "  A DEBUGGABLE third-party package on a production device is a finding"
    echo "  in its own right: it grants run-as, JDWP attach and adb-side debugging"
    echo "  to anyone with shell -- although, as this chapter measures, it does"
    echo "  NOT by itself grant instrumentation."
fi
hr

echo "== next steps =="
cat <<'EOF'
  Declared instrumentation found?
      adb shell am instrument -w -r <testpkg>/<runner>
      and parse it:  | python3 -B parse-instrumentation-results.py --json

  No declared instrumentation?
      The interesting surface is residue inside shipping APKs:
      python3 -B instrumentation-surface.py --pull-device /tmp/corpus

  Want to run YOUR code inside a target?
      You need a test APK whose <instrumentation android:targetPackage> names
      the target, and whose signature matches the target's -- or root. Build one
      with examples/build-instrumentation-fixtures.sh and read README section 3.9
      for the measured gate matrix.
EOF
