#!/usr/bin/env bash
#
# validate-lead.sh -- take ONE lead from static-sweep.py and gather the
#                     evidence needed to confirm it or kill it.
#
# WHAT IT DOES
#   static-sweep.py produces a queue. This works one item of that queue. It is
#   stage 7 of the pipeline in README section 3.7 -- the stage everyone skips,
#   and the reason chapter 33's leak hunter could return 132 high-confidence
#   hits of which 132 were wrong.
#
#   Given a value, a file and line, or a class name, it answers, in order:
#
#     01 SITES         every place the value occurs, each labelled app code,
#                      third-party, generated or resource. A value that occurs
#                      in nine library files and nowhere else is answered
#                      before you read a line of code.
#     02 HOLDER        which class holds it, what that class extends, and
#                      whether it is the app's own package.
#     03 REACHABILITY  an approximate caller closure: who references the
#                      holding class, who references THOSE classes, outward
#                      until it meets a class the manifest declares. If the
#                      closure reaches an entry point, the chain is printed.
#                      If it does not, that is the single most useful thing
#                      this script can tell you -- but read the caveats.
#     04 MANIFEST      is the holding class declared? exported? does the value
#                      itself appear in the manifest or in resources?
#     05 RUNTIME       optional, with --package and a device attached: what
#                      the platform says about the installed app. Read-only:
#                      dumpsys and pm only. Nothing is installed, started,
#                      broadcast or modified.
#     06 KILL LIST     the specific observations that would REFUTE this lead,
#                      written as questions with commands. A lead you have not
#                      tried to kill is a lead you have not validated.
#
#   It prints no verdict, no severity and no colour. It gathers; you decide.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - Whether the lead is a vulnerability. That needs impact, and impact is a
#     conversation with the client about what the asset is worth.
#   - That something IS reachable. The closure is built from textual class
#     references. A class reached through reflection, dependency injection,
#     a service loader, an annotation processor, a lambda captured into a
#     framework callback, or native code has NO textual reference and will not
#     appear. A negative result here is a REASON TO LOOK HARDER, never a
#     proof of unreachability. Chapter 29 measured the general shape of this
#     problem: 299 of 431 broadcast actions live on a real device had no
#     manifest declaration anywhere.
#   - That something is NOT reachable. Same sentence, from the other side.
#   - Anything about obfuscated trees beyond what the names allow. If every
#     class is named `a`, the closure will connect everything to everything
#     and tell you nothing. Deobfuscate first -- chapter 40.
#   - What the value is FOR. Only the code around it says that, and reading
#     it is your job. This script puts the code in front of you.
#
# HOW TO RUN
#     # host -- the common case: a literal value from the sweeper
#     ./validate-lead.sh --tree ./out --value 'TUhMe01PRElGSUVEX1ZBUklBQkxFfQ=='
#
#     # a construct lead: start from the file and line the sweeper printed
#     ./validate-lead.sh --tree ./out --file sources/com/x/Api.java --line 88
#
#     # with the reachability closure (slower: several passes over the tree)
#     ./validate-lead.sh --tree ./out --value 'sk_live_x' --reach
#
#     # two trees, because jadx and apktool see different things
#     ./validate-lead.sh --tree ./jadx-out --tree ./apktool-out --value X
#
#     # add read-only device corroboration. --serial is required whenever more
#     # than one device is attached, which includes a stray emulator.
#     ./validate-lead.sh --tree ./out --value X --package com.example.target
#     ./validate-lead.sh --tree ./out --value X --package com.example.target \
#                        --serial 84f7a024
#
#     # write the evidence pack to a directory you can attach to the report
#     ./validate-lead.sh --tree ./out --value X --out ./evidence/L002
#
# REQUIREMENTS
#   bash, grep, find, sed, awk -- present on macOS, Linux, WSL and Git Bash.
#   adb only for the optional section 05. Nothing else.
#
# RELATED
#   ../README.md section 3.7          stage 7 of the pipeline, in prose
#   ../README.md section 5.5          the four questions a finding must answer
#   ./static-sweep.py                 stage 5 and 6: produce the queue
#   ../examples/triage-worksheet.md   a worked queue
#   ../examples/findings-ledger.csv   a worked queue with the rejections
#   ../labs/lab-02-false-positive-gauntlet.md
#   ../../32-Manifest/README.md       what exported actually means
#   ../../80-Appendix/README.md       the report template and severity rubric
#
# AUTHORISED TESTING ONLY. Only run this against applications you have written
# permission to test.

set -uo pipefail

TREES=""
VALUE=""
FILE=""
LINE=""
CLASSNAME=""
PKG=""
SERIAL=""
OUTDIR=""
DO_REACH=0
MAX_DEPTH=6
CONTEXT=8

# grep prints  path:line:text.  On Windows the path begins `C:/`, so the first
# colon is the drive letter and the obvious ${hit%%:*} split silently yields
# "C" -- which then classifies as unknown and takes the rest of the script
# with it. These two helpers survive both forms.
hit_path() { printf '%s' "$1" | sed -E 's/^(([A-Za-z]:)?[^:]+):[0-9]+:.*$/\1/'; }
hit_line() { printf '%s' "$1" | sed -E 's/^([A-Za-z]:)?[^:]+:([0-9]+):.*$/\2/'; }

say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n%s\n%s\n%s\n' "==============================================================================" "$*" "=============================================================================="; }
sub()  { printf '\n-- %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    sed -n '2,95p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-1}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)   usage 0 ;;
        --tree)      shift; TREES="${TREES}${1:-}"$'\n' ;;
        --value)     shift; VALUE="${1:-}" ;;
        --file)      shift; FILE="${1:-}" ;;
        --line)      shift; LINE="${1:-}" ;;
        --class)     shift; CLASSNAME="${1:-}" ;;
        --package)   shift; PKG="${1:-}" ;;
        --serial)    shift; SERIAL="${1:-}" ;;
        --out)       shift; OUTDIR="${1:-}" ;;
        --reach)     DO_REACH=1 ;;
        --depth)     shift; MAX_DEPTH="${1:-6}" ;;
        --context)   shift; CONTEXT="${1:-8}" ;;
        *)           say "unknown option: $1"; usage 1 ;;
    esac
    shift
done

TREES="$(printf '%s' "$TREES" | sed '/^$/d')"

if [ -z "$TREES" ]; then
    say "error: give at least one --tree (a jadx or apktool output directory)"
    usage 1
fi
if [ -z "$VALUE" ] && [ -z "$FILE" ] && [ -z "$CLASSNAME" ]; then
    say "error: give a --value, a --file (with --line), or a --class"
    usage 1
fi

for t in $TREES; do
    if [ ! -d "$t" ]; then
        say "error: --tree $t is not a directory"
        exit 2
    fi
done

# Everything is written to stdout; --out additionally tees it to a file, so a
# report can cite the evidence pack rather than a screenshot.
if [ -n "$OUTDIR" ]; then
    mkdir -p "$OUTDIR"
    exec > >(tee "$OUTDIR/evidence.txt") 2>&1
fi

# ---------------------------------------------------------------------------
# Path classification -- the same four buckets static-sweep.py uses, so the
# two tools never disagree about whether a file is the app's own code.
# ---------------------------------------------------------------------------

APP_PKG_PATH=""

classify() {   # classify <path> -> app | third-party | generated | resource | unknown
    local p="${1//\\//}"
    local stripped="$p"
    case "$p" in
        */sources/*)          stripped="${p#*/sources/}" ;;
        sources/*)            stripped="${p#sources/}" ;;
        */smali*/*)           stripped="${p#*/smali}"; stripped="${stripped#*/}" ;;
        */src/main/java/*)    stripped="${p#*/src/main/java/}" ;;
    esac
    case "$p" in
        */res/*|res/*|*/assets/*|assets/*) echo "resource"; return ;;
    esac
    case "$(basename "$p")" in
        R.java|R.smali|BuildConfig.java|BuildConfig.smali) echo "generated"; return ;;
        R\$*.java|R\$*.smali|*Binding.java)                echo "generated"; return ;;
        AndroidManifest.xml)                               echo "app"; return ;;
    esac
    if [ -n "$APP_PKG_PATH" ]; then
        case "$stripped" in
            "$APP_PKG_PATH"*) echo "app"; return ;;
        esac
    fi
    case "$stripped" in
        android/*|androidx/*|com/android/*|kotlin/*|kotlinx/*|java/*|javax/*|\
        sun/*|org/jetbrains/*|org/intellij/*|okhttp3/*|okio/*|retrofit2/*|\
        io/reactivex/*|rx/*|org/apache/*|org/json/*|org/w3c/*|org/xml/*|\
        org/xmlpull/*|com/squareup/*|com/google/android/material/*|\
        com/google/android/gms/*|com/google/common/*|com/google/gson/*|\
        com/google/protobuf/*|com/google/firebase/*|dagger/*|com/bumptech/*)
            echo "third-party"; return ;;
    esac
    echo "unknown"
}

# ---------------------------------------------------------------------------
# 00 -- identity
# ---------------------------------------------------------------------------

hdr " validate-lead -- EVIDENCE, NOT A VERDICT"

say "  trees      : $(printf '%s' "$TREES" | tr '\n' ' ')"
[ -n "$VALUE" ]     && say "  value      : $VALUE"
[ -n "$FILE" ]      && say "  file       : $FILE${LINE:+:$LINE}"
[ -n "$CLASSNAME" ] && say "  class      : $CLASSNAME"
[ -n "$PKG" ]       && say "  package    : $PKG"
say "  date       : $(date 2>/dev/null || echo 'unknown')"

MANIFEST=""
for t in $TREES; do
    m="$(find "$t" -name AndroidManifest.xml -not -path '*/original/*' 2>/dev/null | head -1)"
    if [ -n "$m" ]; then MANIFEST="$m"; break; fi
done

if [ -n "$MANIFEST" ]; then
    APP_PKG="$(grep -oE 'package="[A-Za-z0-9_.]+"' "$MANIFEST" 2>/dev/null \
               | head -1 | sed 's/package="//; s/"//')"
    if [ -n "$APP_PKG" ]; then
        APP_PKG_PATH="$(printf '%s' "$APP_PKG" | tr '.' '/')/"
        say "  app package: $APP_PKG   (from $MANIFEST)"
    fi
else
    say "  app package: NOT FOUND -- no AndroidManifest.xml in any tree."
    say "               Every file will classify as unknown, and section 04"
    say "               cannot run. Decode the manifest first."
fi

# ---------------------------------------------------------------------------
# 01 -- sites
# ---------------------------------------------------------------------------

hdr " 01 SITES -- every occurrence, classified"

SITES_RAW="$(mktemp 2>/dev/null || echo "./.validate-sites.$$")"
: > "$SITES_RAW"

if [ -n "$VALUE" ]; then
    for t in $TREES; do
        grep -rnF -- "$VALUE" "$t" 2>/dev/null >> "$SITES_RAW"
    done
elif [ -n "$CLASSNAME" ]; then
    SHORT="${CLASSNAME##*.}"
    for t in $TREES; do
        grep -rnw -- "$SHORT" "$t" 2>/dev/null >> "$SITES_RAW"
    done
elif [ -n "$FILE" ] && [ -n "$LINE" ]; then
    for t in $TREES; do
        if [ -f "$t/$FILE" ]; then
            sed -n "${LINE}p" "$t/$FILE" | sed "s#^#$t/$FILE:$LINE:#" >> "$SITES_RAW"
        fi
    done
fi

N_SITES="$(wc -l < "$SITES_RAW" | tr -d ' ')"
say "  occurrences: $N_SITES"

if [ "$N_SITES" -eq 0 ]; then
    say ""
    say "  ZERO occurrences. Three explanations, in order of likelihood:"
    say "    1. the value was truncated when you copied it out of the report;"
    say "    2. you are searching a different tree from the one swept;"
    say "    3. the sweeper matched a capture group, not the literal line --"
    say "       re-run it with --verbose and copy the line, not the value."
    say ""
    say "  Nothing below will be meaningful. Fix the input first."
fi

APP_SITES=0
LIB_SITES=0
say ""
say "  scope        file:line"
while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    path="$(hit_path "$hit")"
    lineno="$(hit_line "$hit")"
    scope="$(classify "$path")"
    case "$scope" in
        app)     APP_SITES=$((APP_SITES + 1)) ;;
        *)       LIB_SITES=$((LIB_SITES + 1)) ;;
    esac
    printf '  %-12s %s:%s\n' "$scope" "$path" "$lineno"
done < <(head -60 "$SITES_RAW")

if [ "$N_SITES" -gt 60 ]; then
    say "  ... and $((N_SITES - 60)) more (not printed)"
fi

say ""
say "  in app code      : $APP_SITES"
say "  everywhere else  : $LIB_SITES"
say ""
if [ "$APP_SITES" -eq 0 ] && [ "$N_SITES" -gt 0 ]; then
    say "  *** NO SITE IS IN THE APP'S OWN CODE."
    say "  *** This is library behaviour until you show otherwise. It may"
    say "  *** still be a finding -- a library the app ships is the app's"
    say "  *** responsibility -- but the finding is then about the LIBRARY"
    say "  *** and belongs in the dependency section. See chapter 17."
fi

# ---------------------------------------------------------------------------
# 02 -- the holder
# ---------------------------------------------------------------------------

hdr " 02 HOLDER -- the code around the lead"

PRIMARY_FILE=""
PRIMARY_LINE=""
if [ -n "$FILE" ] && [ -n "$LINE" ]; then
    for t in $TREES; do
        if [ -f "$t/$FILE" ]; then PRIMARY_FILE="$t/$FILE"; PRIMARY_LINE="$LINE"; break; fi
    done
fi
if [ -z "$PRIMARY_FILE" ]; then
    # Prefer an app-code site; fall back to the first site of any kind.
    while IFS= read -r hit; do
        [ -z "$hit" ] && continue
        p="$(hit_path "$hit")"
        if [ "$(classify "$p")" = "app" ]; then
            PRIMARY_FILE="$p"; PRIMARY_LINE="$(hit_line "$hit")"; break
        fi
    done < "$SITES_RAW"
fi
if [ -z "$PRIMARY_FILE" ] && [ "$N_SITES" -gt 0 ]; then
    first="$(head -1 "$SITES_RAW")"
    PRIMARY_FILE="$(hit_path "$first")"
    PRIMARY_LINE="$(hit_line "$first")"
fi

HOLDER_CLASS=""
if [ -n "$PRIMARY_FILE" ] && [ -f "$PRIMARY_FILE" ]; then
    say "  file  : $PRIMARY_FILE"
    say "  scope : $(classify "$PRIMARY_FILE")"
    pkgline="$(grep -m1 -E '^\s*package\s+' "$PRIMARY_FILE" 2>/dev/null \
               | sed 's/^[[:space:]]*//')"
    [ -n "$pkgline" ] && say "  $pkgline"
    HOLDER_CLASS="$(basename "$PRIMARY_FILE")"
    HOLDER_CLASS="${HOLDER_CLASS%.java}"
    HOLDER_CLASS="${HOLDER_CLASS%.kt}"
    HOLDER_CLASS="${HOLDER_CLASS%.smali}"
    say "  class : $HOLDER_CLASS"

    sub "declaration"
    grep -nE '^\s*(public|private|protected|final|abstract|open|internal)?\s*(final\s+)?(class|interface|enum|object)\s+' \
        "$PRIMARY_FILE" 2>/dev/null | head -5 | sed 's/^/    /'

    sub "the enclosing method (best effort -- searched upward from the hit)"
    if [ -n "$PRIMARY_LINE" ]; then
        awk -v target="$PRIMARY_LINE" '
            NR <= target && /(\(.*\)\s*\{|\bfun\b|\bvoid\b|\bpublic\b|\bprivate\b)/ { last = NR ": " $0 }
            END { if (last != "") print "    " last }
        ' "$PRIMARY_FILE"
    fi

    sub "context (+/- $CONTEXT lines)"
    if [ -n "$PRIMARY_LINE" ]; then
        start=$((PRIMARY_LINE - CONTEXT)); [ "$start" -lt 1 ] && start=1
        end=$((PRIMARY_LINE + CONTEXT))
        awk -v s="$start" -v e="$end" -v t="$PRIMARY_LINE" \
            'NR>=s && NR<=e { printf "  %s %5d  %s\n", (NR==t?">>":"  "), NR, $0 }' \
            "$PRIMARY_FILE"
    fi

    sub "what else this file does -- the corroboration the sweeper counted"
    for pat in 'Cipher|SecretKey|KeyGenerator|encrypt|decrypt' \
               'https?://|Retrofit|OkHttp|HttpURLConnection|@POST|@GET' \
               'Authorization|Bearer|addHeader|setRequestProperty' \
               'SharedPreferences|getSharedPreferences|openFileOutput' \
               'Intent|startActivity|sendBroadcast|bindService' \
               'BuildConfig\.DEBUG|isDebug'; do
        # `grep -c || echo 0` prints TWO lines when grep finds nothing: its
        # own 0 and the fallback. `[ "0\n0" -gt 0 ]` is a syntax error, not a
        # false, so the whole loop fails noisily. Take the first line only.
        n="$(grep -cE "$pat" "$PRIMARY_FILE" 2>/dev/null | head -1)"
        [ -z "$n" ] && n=0
        [ "$n" -gt 0 ] && printf '    %-3s %s\n' "$n" "$pat"
    done
else
    say "  No file to open. Section 01 found nothing usable."
fi

# ---------------------------------------------------------------------------
# 03 -- reachability
# ---------------------------------------------------------------------------

hdr " 03 REACHABILITY -- approximate caller closure"

if [ "$DO_REACH" -eq 0 ]; then
    say "  Skipped. Pass --reach to run it."
    say ""
    say "  It is skipped by default because it makes several passes over the"
    say "  whole tree and takes tens of seconds. It is also the single most"
    say "  valuable thing in this script: a lead that no entry point can"
    say "  reach is a lead whose severity collapses."
elif [ -z "$HOLDER_CLASS" ]; then
    say "  Cannot run: no holding class was identified in section 02."
elif [ -z "$MANIFEST" ]; then
    say "  Cannot run: no manifest, so there are no entry points to reach."
else
    # Only android:name on a COMPONENT element is an entry point. A naive
    # `grep android:name` also collects <action>, <category>, <meta-data> and
    # <uses-permission> values -- and android.intent.action.MAIN then looks
    # like a class, which makes the closure claim success against nothing.
    ENTRY="$(mktemp 2>/dev/null || echo "./.validate-entry.$$")"
    # No `\b` in these patterns. POSIX awk has no word-boundary escape, and
    # gawk reads `\b` as a BACKSPACE character, so `/<activity\b/` silently
    # matches nothing at all -- the entry-point list came out empty and the
    # closure then reported "no path to any entry point" for a class that was
    # declared in the manifest three lines further down.
    awk '
        /<(intent-filter|meta-data|action|category|data|uses-permission|permission|uses-sdk|uses-feature|uses-library|grant-uri-permission|path-permission)[ \t>\/]/ { intag = 0 }
        /<(activity|activity-alias|service|receiver|provider|application)([ \t>\/]|$)/  { intag = 1 }
        intag && match($0, /android:name="[^"]+"/) {
            print substr($0, RSTART + 14, RLENGTH - 15); intag = 0
        }
    ' "$MANIFEST" | sed "s/^\./${APP_PKG}./" | sort -u > "$ENTRY"
    n_entry="$(wc -l < "$ENTRY" | tr -d ' ')"
    say "  entry points declared in the manifest: $n_entry"
    say "  (activities, services, receivers, providers and the Application"
    say "   class -- the only classes the PLATFORM can start directly)"
    say ""

    # Depth 0. If the holder IS an entry point, everything below is noise --
    # and expensive noise: each further depth greps the whole tree once per
    # class in the frontier, which on a 3,600-file tree is minutes.
    DEPTH0=0
    if grep -qE "(^|\.)${HOLDER_CLASS}\$" "$ENTRY" 2>/dev/null; then
        DEPTH0=1
        say "  DEPTH 0: the holding class is ITSELF declared in the manifest:"
        grep -E "(^|\.)${HOLDER_CLASS}\$" "$ENTRY" | sed 's/^/      /'
        say ""
        say "  The platform can start this class directly. Reachability is not"
        say "  in question; what remains is WHO can start it (section 04's"
        say "  android:exported and android:permission) and what the lead is"
        say "  guarded by inside the class."
        say ""
    fi

    FRONTIER="$(mktemp 2>/dev/null || echo "./.validate-frontier.$$")"
    SEEN="$(mktemp 2>/dev/null || echo "./.validate-seen.$$")"
    printf '%s\n' "$HOLDER_CLASS" > "$FRONTIER"
    printf '%s\n' "$HOLDER_CLASS" > "$SEEN"

    depth=0
    reached=""
    [ "$DEPTH0" -eq 1 ] && depth="$MAX_DEPTH"   # nothing left to prove
    while [ "$depth" -lt "$MAX_DEPTH" ]; do
        depth=$((depth + 1))
        NEXT="$(mktemp 2>/dev/null || echo "./.validate-next.$$.$depth")"
        : > "$NEXT"
        while IFS= read -r cls; do
            [ -z "$cls" ] && continue
            for t in $TREES; do
                grep -rlw -- "$cls" "$t" 2>/dev/null | while IFS= read -r f; do
                    b="$(basename "$f")"
                    b="${b%.java}"; b="${b%.kt}"; b="${b%.smali}"
                    [ "$b" = "$cls" ] && continue
                    printf '%s\n' "$b"
                done
            done
        done < "$FRONTIER" | sort -u > "$NEXT"

        # Anything already seen is not new information.
        comm -23 "$NEXT" <(sort -u "$SEEN") > "$NEXT.new" 2>/dev/null \
            || cp "$NEXT" "$NEXT.new"
        n_new="$(wc -l < "$NEXT.new" | tr -d ' ')"
        say "  depth $depth: $n_new new referencing class(es)"

        # A frontier that has exploded is not telling you anything: at a few
        # hundred classes the closure has reached the framework and everything
        # is "reachable from everything". Stop and say so rather than grind
        # for ten minutes and print a meaningless success.
        if [ "$n_new" -gt 250 ]; then
            say ""
            say "  FRONTIER EXPLODED ($n_new classes at depth $depth)."
            say "  The closure has escaped into framework and utility classes,"
            say "  where name references connect everything to everything. Any"
            say "  'reachable' answer from here would be an artefact of the"
            say "  method, not a fact about the app. Narrow it instead:"
            say "    - start from the specific METHOD, not the class;"
            say "    - use jadx-gui's 'Find Usage' on the field or method;"
            say "    - or answer the question dynamically with a Frida hook."
            rm -f "$NEXT" "$NEXT.new"
            break
        fi

        if [ "$n_new" -eq 0 ]; then
            say "  closure is complete at depth $depth"
            rm -f "$NEXT" "$NEXT.new"
            break
        fi

        # Did we reach an entry point?
        hit="$(while IFS= read -r c; do
                   grep -E "(^|\.)${c}$" "$ENTRY" 2>/dev/null | head -1
               done < "$NEXT.new" | head -1)"
        cat "$NEXT.new" >> "$SEEN"
        sort -u -o "$SEEN" "$SEEN"
        mv "$NEXT.new" "$FRONTIER"
        rm -f "$NEXT"

        if [ -n "$hit" ]; then
            reached="$hit"
            say ""
            say "  REACHED a manifest-declared entry point at depth $depth:"
            say "      $hit"
            break
        fi
    done

    say ""
    if [ "$DEPTH0" -eq 1 ]; then
        say "  Closure not run: the holder is an entry point in its own right,"
        say "  which is a stronger result than any closure could produce."
    elif [ -n "$reached" ]; then
        say "  A textual path exists from the lead to a class the platform can"
        say "  start. That is EVIDENCE of reachability, not proof: the path is"
        say "  made of name references, and a reference is not a call."
        say ""
        say "  Confirm it by execution, not by reading. Set a Frida hook on"
        say "  the holding method and drive the app -- chapter 53. A hook that"
        say "  never fires during normal use is worth reporting as such."
    else
        say "  NO textual path to any manifest entry point within depth"
        say "  $MAX_DEPTH."
        say ""
        say "  Do not write 'unreachable'. Write 'no static path found', and"
        say "  then go and check the five ways a path can exist without a"
        say "  textual reference:"
        say "    1. reflection            grep for Class.forName and invoke"
        say "    2. dependency injection  Dagger/Hilt/Koin wire by type"
        say "    3. ServiceLoader / SPI   META-INF/services/ entries"
        say "    4. a runtime-registered receiver or a callback the framework"
        say "       holds -- chapter 29 measured 69% of the broadcast surface"
        say "       living exactly here"
        say "    5. native code calling back through JNI -- chapter 16"
    fi
    rm -f "$ENTRY" "$FRONTIER" "$SEEN"
fi

# ---------------------------------------------------------------------------
# 04 -- manifest cross-check
# ---------------------------------------------------------------------------

hdr " 04 MANIFEST -- declaration, export, and the value itself"

if [ -z "$MANIFEST" ]; then
    say "  No manifest available."
else
    say "  manifest: $MANIFEST"
    if [ -n "$HOLDER_CLASS" ]; then
        sub "is the holding class declared as a component?"
        if grep -nE "android:name=\"[^\"]*\.?${HOLDER_CLASS}\"" "$MANIFEST" >/dev/null 2>&1; then
            grep -nE -B2 -A8 "android:name=\"[^\"]*\.?${HOLDER_CLASS}\"" \
                "$MANIFEST" 2>/dev/null | sed 's/^/    /' | head -30
            say ""
            say "    Read android:exported and android:permission on that"
            say "    element yourself. Chapter 32 owns the semantics, including"
            say "    the case that matters most: no android:exported attribute"
            say "    plus an intent-filter means EXPORTED on targetSdk < 31."
        else
            say "    Not declared. The class is reached from other code, not"
            say "    started by the platform."
        fi
    fi
    if [ -n "$VALUE" ]; then
        sub "does the value appear in the manifest or in resources?"
        found=0
        for t in $TREES; do
            for f in "$MANIFEST" \
                     "$(find "$t" -path '*res/values*' -name 'strings.xml' 2>/dev/null | head -3)"; do
                [ -f "$f" ] || continue
                if grep -nF -- "$VALUE" "$f" >/dev/null 2>&1; then
                    grep -nF -- "$VALUE" "$f" | sed "s#^#    $f:#" | head -5
                    found=1
                fi
            done
        done
        [ "$found" -eq 0 ] && say "    Not present in the manifest or in strings.xml."
        say ""
        say "    A value that lives in res/values/strings.xml is trivially"
        say "    extractable and survives R8 renaming. That does not make it"
        say "    worse than one in the DEX -- both are readable by anyone with"
        say "    the APK -- but it does mean 'obfuscation would fix it' is a"
        say "    wrong recommendation."
    fi
fi

# ---------------------------------------------------------------------------
# 05 -- runtime corroboration (read-only)
# ---------------------------------------------------------------------------

hdr " 05 RUNTIME -- what the platform says (read-only)"

if [ -z "$PKG" ]; then
    say "  Skipped. Pass --package <pkg> with a device attached."
elif ! have adb; then
    say "  Skipped: adb is not on PATH."
else
    # `tr -d '\r'` first: on Windows every line of `adb devices` ends CRLF, so
    # a `grep 'device$'` counts zero and the whole section silently skips.
    devices="$(adb devices 2>/dev/null | tr -d '\r' | sed -n '2,$p' \
               | grep -c 'device$')"
    ADB="adb"
    [ -n "$SERIAL" ] && ADB="adb -s $SERIAL"
    if [ "${devices:-0}" -eq 0 ]; then
        say "  Skipped: no device in 'adb devices'."
    elif [ "${devices:-0}" -gt 1 ] && [ -z "$SERIAL" ]; then
        say "  Skipped: $devices devices attached and no --serial given."
        say "  adb would answer 'more than one device/emulator' for every"
        say "  command below. Pick one:"
        adb devices -l 2>/dev/null | tr -d '\r' | sed -n '2,$p' | sed 's/^/    /'
        say "      ./validate-lead.sh ... --serial <the one you mean>"
        say ""
        say "  Which device matters more than it looks: an emulator and a"
        say "  physical phone give different answers about flags, about the"
        say "  trust store, and about whether an app is even installed."
    else
        sub "installed paths (all splits -- analysing base.apk alone is a"
        sub "classic way to conclude a feature is absent when it is not)"
        $ADB shell pm path "$PKG" 2>/dev/null | tr -d '\r' | sed 's/^/    /'

        sub "flags the platform actually applied"
        $ADB shell dumpsys package "$PKG" 2>/dev/null | tr -d '\r' \
            | grep -E 'versionName|versionCode|targetSdk|minSdk|flags=|privateFlags=|installerPackageName|firstInstallTime' \
            | head -12 | sed 's/^/    /'
        say ""
        say "    DEBUGGABLE in flags= is the platform's own answer to the"
        say "    debuggable lead, and it beats the manifest you decoded,"
        say "    because it is what the system installed rather than what a"
        say "    file claims."

        sub "declared components as the platform resolved them"
        $ADB shell dumpsys package "$PKG" 2>/dev/null | tr -d '\r' \
            | sed -n '/Activity Resolver Table/,/Service Resolver Table/p' \
            | head -20 | sed 's/^/    /'
    fi
fi

# ---------------------------------------------------------------------------
# 06 -- the kill list
# ---------------------------------------------------------------------------

hdr " 06 KILL LIST -- try to refute this lead before you report it"

cat <<'KILL'
  A lead you have not tried to kill is a lead you have not validated. Work
  down this list and write the answer next to each one, in the ledger, even
  when the answer is "yes, still stands". The rejections are the part of a
  report that shows the work was done.

  1. Is it in the app's own code, or in a library?
       Section 01 answers this. A finding about okhttp is a finding about
       okhttp; it belongs in the dependency section, phrased as a version.

  2. Is the value a value, or a NAME?
       "api_key" as a JSON key or a preference name is not a credential.
       Read the line: is the secret next to the name, or is the name a lookup
       into something fetched at runtime?

  3. Does it decode to something meaningful?
       echo 'VALUE' | base64 -d | xxd | head
       A base64 blob that decodes to a UI string is a UI string.

  4. Is the code dead?
       Section 03. Also check: is it behind BuildConfig.DEBUG? R8 strips
       those branches in release builds, and the decompiler may still show
       them if you decompiled a debug artefact.

  5. Did you analyse the SHIPPED artefact?
       adb shell pm path <pkg>, pull every path it prints, hash it, and
       compare. A finding derived from a debug build you compiled yourself
       is not a finding about the product.

  6. Is the mechanism actually dangerous here?
       Google API keys, Lokalise tokens, Firebase app ids and Play Billing
       public keys are DESIGNED to ship in clients. The finding is never
       "a key was present"; it is "this key has no restriction and this
       scope", and you have to check the restriction.

  7. Does the control you think is missing exist somewhere else?
       Chapter 36 measured 12 of 14 apps presenting a pinning surface while
       only 4 actually pinned -- and the inverse error is just as common:
       concluding "no pinning" from one class when the pin sits in the
       network security config XML.

  8. Would the client's own logs corroborate it?
       Ask. A five-minute question can convert a Medium into a High or
       delete it entirely.

  If the lead survives all eight, it is a finding. Write it up with:
  the artefact hash, the file and line, the evidence pack from this script,
  a demonstration, honest severity, and the fix as code. The template lives
  in chapter 80.
KILL

hdr " Nothing above is a verdict."

say ""
say "  This script gathered evidence. Severity is yours, and it comes from"
say "  reachability, from who can reach it, and from what reaching it gets"
say "  them -- not from the fact that a string exists in a file."
say ""
[ -n "$OUTDIR" ] && say "  Evidence pack written to $OUTDIR/evidence.txt"

rm -f "$SITES_RAW"
