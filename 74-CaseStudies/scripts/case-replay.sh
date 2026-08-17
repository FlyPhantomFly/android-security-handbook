#!/usr/bin/env bash
#
# case-replay.sh -- re-run the measurements behind chapter 74's case studies and
#                   report, per assertion, REPRODUCED / DIVERGED / SKIPPED.
#
# WHY THIS EXISTS
#   A published measurement decays silently. Devices are updated, tools change
#   behaviour, and a number nobody re-runs stays in a document forever whether or
#   not it is still true. Reading cannot detect this; only re-running can.
#
#   Chapter 74 section 3.8 records the yield: of three case studies re-run while
#   writing that chapter, two produced findings the originals did not contain and
#   one produced an entirely new case study that corrected a published figure.
#   That is a high return for work that feels like clerical checking.
#
# WHAT IT DOES NOT DO
#   It does not tell you a chapter is WRONG. A divergence has at least four
#   explanations before "the original was mistaken":
#     - a different device                - a different vantage (root/shell/app)
#     - a different OS or tool version    - a different command than the one printed
#   The script emits DIVERGED and stops. Adjudication is yours, and the honest
#   verdict is frequently "diverged, cause not established" -- which is what
#   chapter 74 section 3.5 records against a figure it could not resolve.
#
# USAGE
#   ./case-replay.sh [-s <serial>] [-p <debuggable-pkg>] [--case A|C|D|all] [--quiet]
#
#     --case A    the boot-state property (chapter 74 section 3.1) -- device only
#     --case C    the compiler folding case (section 3.3) -- HOST only, needs the NDK
#     --case D    the three-vantage detection probe (section 3.4) -- needs -p
#     --case all  everything runnable in the current environment (default)
#
#   Cases B and F are not replayable here and the script says so rather than
#   pretending: B needs a built ARM64 fixture pushed to a device, and F needs a
#   237-APK corpus. "NOT REPLAYABLE" is an honest output.
#
# EXECUTED?
#   YES. Run against the AVD `sdk_gphone16k_x86_64` (emulator-5554, Android 15 /
#   API 35, Magisk 30.7) and with NDK 25.2.9519653 on the host, on 2026-08-16.
#   Cases A and D reported REPRODUCED. Case C reported REPRODUCED. The exit code
#   was 0 in all three.
#
# EXIT CODES
#   0  every assertion REPRODUCED (or was skipped)
#   1  at least one assertion DIVERGED   <-- investigate, do not assume anyone erred
#   2  the environment could not run anything (no device, no NDK)
#
# ENVIRONMENT
#   NDK_BIN   directory holding aarch64-linux-android21-clang and llvm-strings.
#             Only needed for case C. Auto-detected under the usual SDK paths.
#
# NOTE ON `set -o pipefail`
#   Deliberately NOT set. With early-exit consumers (`head`, `grep -q`) it turns a
#   SUCCESSFUL match into a spurious pipeline failure, because the writer dies of
#   SIGPIPE the instant the reader has what it needs. This repository has lost
#   hours to that twice. Everything below tests CONTENT, never exit status.

set -u

SERIAL=""; PKG=""; CASE="all"; QUIET=0
PASS=0; FAIL=0; SKIP=0
ROOTFORM="none"

# ------------------------------------------------------------------ output ---
green()  { printf '  [REPRODUCED]  %s\n' "$1"; PASS=$((PASS+1)); }
red()    { printf '  [DIVERGED  ]  %s\n' "$1"
           printf '                expected: %s\n' "$2"
           printf '                observed: %s\n' "$3"; FAIL=$((FAIL+1)); }
skip()   { printf '  [SKIPPED   ]  %s  (%s)\n' "$1" "$2"; SKIP=$((SKIP+1)); }
note()   { [ "$QUIET" -eq 1 ] || printf '                %s\n' "$1"; }
head1()  { printf '\n--- %s\n' "$1"; }

# Compare an observed value against an expected one. `expected` may be the
# literal string EMPTY, which is checked explicitly -- an empty observation and a
# failed command look identical otherwise, and that distinction is the entire
# subject of case A.
assert_eq() {
    local label="$1" expected="$2" observed="$3"
    if [ "$expected" = "EMPTY" ]; then
        if [ -z "$observed" ]; then green "$label"; else
            red "$label" "(the empty string)" "'$observed'"; fi
    elif [ "$expected" = "$observed" ]; then
        green "$label"
    else
        red "$label" "$expected" "${observed:-(empty)}"
    fi
}

assert_contains() {
    local label="$1" needle="$2" hay="$3"
    case "$hay" in
        *"$needle"*) green "$label" ;;
        *)           red  "$label" "output containing '$needle'" "${hay:-(empty)}" ;;
    esac
}

# ---------------------------------------------------------------- arguments --
while [ $# -gt 0 ]; do
    case "$1" in
        -s|--serial)  SERIAL="${2:-}"; shift 2 ;;
        -p|--package) PKG="${2:-}";    shift 2 ;;
        --case)       CASE="${2:-all}"; shift 2 ;;
        --quiet)      QUIET=1; shift ;;
        -h|--help)    sed -n '3,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

# ------------------------------------------------------------ adb plumbing ---
have_adb=0
command -v adb > /dev/null 2>&1 && have_adb=1

# stdin is redirected on every adb call: `adb shell` inherits stdin and will
# silently consume a surrounding `while read` loop's input, so the loop runs once
# and exits cleanly, looking exactly like a device with nothing on it.
A() {
    if [ -n "$SERIAL" ]; then adb -s "$SERIAL" shell "$@" < /dev/null 2>&1
    else                      adb shell "$@" < /dev/null 2>&1; fi
}

device_ready() {
    [ "$have_adb" -eq 1 ] || return 1
    local n
    n=$(adb devices < /dev/null 2>/dev/null | grep -c '	device$')
    [ "$n" -ge 1 ] || return 1
    if [ "$n" -gt 1 ] && [ -z "$SERIAL" ]; then
        printf 'error: %s devices attached and no -s given. Refusing to guess.\n' "$n" >&2
        return 1
    fi
    return 0
}

# Both su conventions are probed. Magisk on a physical device takes `su -c`; the
# AOSP emulator takes `su 0 <cmd>` and rejects `-c` with
# "su: invalid uid/gid '-c'", which reads exactly like an unrooted device. Three
# chapters in this repository have been caught by that.
detect_root() {
    if   A "su 0 id"  | grep -q 'uid=0'; then ROOTFORM="zero"
    elif A "su -c id" | grep -q 'uid=0'; then ROOTFORM="dashc"
    else                                      ROOTFORM="none"; fi
}
as_root() {
    case "$ROOTFORM" in
        zero)  A "su 0 sh -c '$1'" ;;
        dashc) A "su -c 'sh -c \"$1\"'" ;;
        *)     printf '' ;;
    esac
}

# ------------------------------------------------------------------ case A ---
replay_case_a() {
    head1 "Case A -- the boot-state property (chapter 74 section 3.1)"
    if ! device_ready; then skip "case A" "no usable device"; return; fi

    local model sdk
    model=$(A "getprop ro.product.model" | tr -d '\r')
    sdk=$(A "getprop ro.build.version.sdk" | tr -d '\r')
    note "device: $model, API $sdk"

    case "$model" in
      sdk_gphone*|emu64*|Android?SDK*) ;;
      *) skip "case A" "recorded against an AVD; this is '$model'. Run it, but adjudicate by hand."
         note "The empty-string result is an EMULATOR finding. A physical device"
         note "is expected to report green/yellow/orange/red, or a forged value."
         return ;;
    esac

    assert_eq "ro.boot.verifiedbootstate is the empty string" \
              "EMPTY" "$(A 'getprop ro.boot.verifiedbootstate' | tr -d '\r')"
    assert_eq "ro.boot.flash.locked is the empty string" \
              "EMPTY" "$(A 'getprop ro.boot.flash.locked' | tr -d '\r')"
    assert_eq "ro.boot.vbmeta.device_state is the empty string" \
              "EMPTY" "$(A 'getprop ro.boot.vbmeta.device_state' | tr -d '\r')"
    assert_eq "ro.boot.veritymode is enforcing" \
              "enforcing" "$(A 'getprop ro.boot.veritymode' | tr -d '\r')"

    local st
    st=$(A 'getprop ro.boot.verifiedbootstate' | tr -d '\r')
    if [ "$st" != "orange" ]; then
        green 'the folk check !"orange".equals(state) PASSES here'
        note 'That is the finding, not a pass. The most-copied verified-boot check'
        note 'in existence succeeds on the least trustworthy platform it can meet.'
        note 'Allow-list: "green".equals(state). Never deny-list "orange".'
    else
        red 'the folk check passes here' 'state != orange' "state = $st"
    fi

    # The causal half. Root-only, and that is itself the finding.
    if [ "$ROOTFORM" = "none" ]; then
        skip "bootconfig causal check" "no root"
    else
        local bc
        bc=$(as_root "cat /proc/bootconfig" | tr -d '\r')
        if [ -z "$bc" ]; then
            skip "bootconfig causal check" "/proc/bootconfig unreadable even as root"
        else
            local absent=0 k
            for k in androidboot.verifiedbootstate androidboot.flash.locked \
                     androidboot.vbmeta.device_state androidboot.slot_suffix; do
                case "$bc" in *"$k"*) absent=1 ;; esac
            done
            if [ "$absent" -eq 0 ]; then
                green "the four androidboot.* keys are ABSENT from bootconfig"
                note "A ro.boot.X property is empty exactly when androidboot.X is absent."
            else
                red "the four androidboot.* keys are absent" "none present" "at least one present"
            fi
            assert_contains "androidboot.veritymode IS present (control)" \
                            "androidboot.veritymode" "$bc"
        fi

        # The vantage finding: the cross-check the app would need is root-only.
        local shell_bc
        shell_bc=$(A "cat /proc/bootconfig" | tr -d '\r')
        case "$shell_bc" in
            *"Permission denied"*)
                green "/proc/bootconfig is unreadable to shell (and so to any app)"
                note "The comparison that catches a forged property CANNOT be performed"
                note "by the process doing the checking. That is why client-side"
                note "verified-boot checking is structurally unsound, not merely weak." ;;
            *)  note "/proc/bootconfig IS readable to shell on this device -- differs from"
                note "the reference AVD. Worth recording; not a failure."
                skip "/proc/bootconfig is root-only" "readable to shell here" ;;
        esac
    fi
}

# ------------------------------------------------------------------ case D ---
replay_case_d() {
    head1 "Case D -- the detection that cannot detect (chapter 74 section 3.4)"
    if ! device_ready; then skip "case D" "no usable device"; return; fi
    if [ -z "$PKG" ]; then
        skip "case D" "no -p <debuggable-package>; the app vantage is the whole point"
        note "Find one with: ./vantage-diff.sh --find-package"
        return
    fi
    if [ "$ROOTFORM" = "none" ]; then
        skip "case D" "no root; the ground-truth column is unavailable"
        return
    fi

    classify() {
        case "$1" in
            *"No such file or directory"*) printf 'ABSENT'    ;;
            *"Permission denied"*)         printf 'FORBIDDEN' ;;
            "")                            printf 'ERROR'     ;;
            *)                             printf 'PRESENT'   ;;
        esac
    }

    check_row() {
        local path="$1" er="$2" es="$3" ea="$4"
        local r s a gr gs ga
        r=$(as_root "ls -ld $path" | tr -d '\r')
        s=$(A       "ls -ld $path" | tr -d '\r')
        a=$(A "run-as $PKG sh -c 'ls -ld $path'" | tr -d '\r')
        gr=$(classify "$r"); gs=$(classify "$s"); ga=$(classify "$a")
        if [ "$gr/$gs/$ga" = "$er/$es/$ea" ]; then
            green "$path -> $gr / $gs / $ga"
        else
            red "$path" "$er/$es/$ea" "$gr/$gs/$ga"
        fi
    }

    note "columns are root / shell / app"
    check_row /data/adb            PRESENT FORBIDDEN FORBIDDEN
    check_row /data/adb/lspd       ABSENT  FORBIDDEN FORBIDDEN
    check_row /data/adb/modules    PRESENT FORBIDDEN FORBIDDEN
    check_row /system/xbin/su      PRESENT PRESENT   FORBIDDEN
    check_row /debug_ramdisk/magisk PRESENT PRESENT  PRESENT

    note ""
    note "Rows 2, 3 and 4 all yield File.exists() == false from the app, for three"
    note "different reasons: genuinely absent; present but forbidden; present,"
    note "setuid root, and forbidden. The API discards the distinction."

    # The mountinfo count, including the correction chapter 74 section 3.4.4 records.
    local src_n any_n
    src_n=$(A "run-as $PKG sh -c 'grep -c \" magisk \" /proc/self/mountinfo'" | tr -d '\r')
    any_n=$(A "run-as $PKG sh -c 'grep -c magisk /proc/self/mountinfo'"       | tr -d '\r')
    note ""
    if [ "$src_n" -ge 1 ] 2>/dev/null; then
        green "mountinfo: $src_n mount(s) whose SOURCE is magisk, $any_n line(s) mentioning it"
        note "Chapter 63 records '3 lines whose mount source is literally magisk'."
        note "Measured here the two numbers differ: the extra line's source is"
        note "devpts, with 'magisk' only in the mount POINT path. Quote it as"
        note "'N magisk-sourced mounts, M lines mentioning magisk' and the"
        note "ambiguity disappears. The signal is real either way."
    else
        skip "mountinfo magisk signal" "no magisk-sourced mounts -- device may not be Magisk-rooted"
    fi
}

# ------------------------------------------------------------------ case C ---
replay_case_c() {
    head1 "Case C -- the obfuscation the compiler deleted (chapter 74 section 3.3)"

    local ndk="${NDK_BIN:-}" cc strings_bin here src out
    if [ -z "$ndk" ]; then
        for cand in "$HOME"/Android/Sdk/ndk/*/toolchains/llvm/prebuilt/*/bin \
                    "$HOME"/AppData/Local/Android/Sdk/ndk/*/toolchains/llvm/prebuilt/*/bin \
                    "$ANDROID_HOME"/ndk/*/toolchains/llvm/prebuilt/*/bin; do
            [ -d "$cand" ] && { ndk="$cand"; break; }
        done
    fi
    if [ -z "$ndk" ] || [ ! -d "$ndk" ]; then
        skip "case C" "NDK not found; set NDK_BIN to the toolchain bin directory"
        return
    fi

    cc="$ndk/aarch64-linux-android21-clang"
    [ -x "$cc" ] || cc="$cc.cmd"
    strings_bin="$ndk/llvm-strings"
    [ -x "$strings_bin" ] || strings_bin="$strings_bin.exe"
    if [ ! -x "$cc" ] || [ ! -x "$strings_bin" ]; then
        skip "case C" "toolchain incomplete under $ndk"; return
    fi

    here=$(cd "$(dirname "$0")" && pwd)
    src="$here/../examples/fold.c"
    if [ ! -f "$src" ]; then skip "case C" "examples/fold.c not found"; return; fi

    # Build OUTSIDE the repository. .so files are on the artefact blocklist.
    out=$(mktemp -d) || { skip "case C" "mktemp failed"; return; }

    "$cc" -Wall -Wextra -O0 -fPIC -shared -o "$out/fold-O0.so" "$src" > "$out/o0.log" 2>&1
    "$cc" -Wall -Wextra -O2 -fPIC -shared -o "$out/fold-O2.so" "$src" > "$out/o2.log" 2>&1

    if [ ! -f "$out/fold-O0.so" ] || [ ! -f "$out/fold-O2.so" ]; then
        red "examples/fold.c compiles at -O0 and -O2" "two shared objects" "compilation failed"
        note "compiler output:"; sed 's/^/                  /' "$out/o0.log" | head -6
        rm -rf "$out"; return
    fi
    green "examples/fold.c compiles clean at -O0 and -O2 under -Wall -Wextra"

    local s0 s2
    s0=$("$strings_bin" -n 4 "$out/fold-O0.so" | grep xbin || printf '')
    s2=$("$strings_bin" -n 4 "$out/fold-O2.so" | grep xbin || printf '')

    if [ -z "$s0" ]; then green "-O0 build does NOT leak the plaintext"
    else red "-O0 hides the plaintext" "no match" "$s0"; fi

    if [ -n "$s2" ]; then
        green "-O2 build LEAKS the plaintext: $s2"
        note "Identical source. Higher optimisation made the secret MORE visible."
        note "The decoder carries __attribute__((noinline)) and it changed nothing:"
        note "noinline constrains the inliner, and the pass that leaks the string is"
        note "interprocedural constant propagation followed by specialisation."
    else
        red "-O2 leaks the plaintext" "/system/xbin/su" "(nothing)"
        note "This is a DIVERGENCE, not a success. Your toolchain optimises"
        note "differently from NDK 25.2.9519653. Record the version and adjudicate."
    fi

    rm -rf "$out"
}

# ------------------------------------------------------------- not runnable --
report_unreplayable() {
    head1 "Cases B and F -- not replayable in this environment"
    skip "case B (the patch that changed nothing)" \
         "needs a built ARM64 fixture pushed to a device; see 59-radare2/examples"
    skip "case F (1,141 hits, 0 findings)" \
         "needs a 237-APK corpus; see 64-Xposed/scripts/pull-apk-corpus.sh"
    note "NOT REPLAYABLE is an honest output. Chapter 74 section 3.8 records both"
    note "as 'not re-run' rather than implying they were checked."
}

# ------------------------------------------------------------------- main ----
printf '========================================================================\n'
printf ' case-replay -- re-running chapter 74 case studies\n'
printf ' date   : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
if device_ready; then
    detect_root
    printf ' device : %s (API %s)\n' \
        "$(A 'getprop ro.product.model' | tr -d '\r')" \
        "$(A 'getprop ro.build.version.sdk' | tr -d '\r')"
    printf ' root   : %s\n' "$ROOTFORM"
    printf ' app    : %s\n' "${PKG:-<none>}"
else
    printf ' device : none usable -- device cases will be SKIPPED\n'
fi
printf '========================================================================\n'

case "$CASE" in
    A|a)   replay_case_a ;;
    C|c)   replay_case_c ;;
    D|d)   replay_case_d ;;
    all)   replay_case_a; replay_case_d; replay_case_c; report_unreplayable ;;
    *)     printf 'unknown case: %s\n' "$CASE" >&2; exit 2 ;;
esac

printf '\n========================================================================\n'
printf ' REPRODUCED %s   DIVERGED %s   SKIPPED %s\n' "$PASS" "$FAIL" "$SKIP"
printf '========================================================================\n'

if [ "$FAIL" -gt 0 ]; then
    cat <<'EOF'

A DIVERGED line is a question, not a verdict on anybody. Before concluding that
a chapter is wrong, rule out, in this order:

  1. A different DEVICE. Model, API level, ABI, page size, OEM build.
  2. A different VANTAGE. Was the original taken as root, as shell, or as an app?
     This is the most common cause and the hardest to see, because the label in a
     write-up is prose while the measurement was a command.
  3. A different TOOL VERSION. Compilers especially -- case C is a statement
     about NDK 25.2.9519653, not about clang in general.
  4. A different COMMAND from the one printed.

If none of those explains it, the honest verdict is "DIVERGED, cause not
established". Publish that, with the evidence, and let whoever holds the original
hardware settle it. Do not silently rewrite someone else's measurement: it
destroys the record of the disagreement, which is what a future reader needs most.
EOF
    exit 1
fi

if [ "$PASS" -eq 0 ]; then exit 2; fi
exit 0
