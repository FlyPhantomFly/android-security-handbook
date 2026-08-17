#!/usr/bin/env bash
#
# provider-enum.sh — enumerate and probe every ContentProvider on a device or in an APK.
#
# WHAT IT DOES
#   Four subcommands, in the order you would actually use them:
#
#     device            Every provider registered on the device: authority, owning
#                       package, exported state, read/write permission (with its
#                       resolved protectionLevel), grantUriPermissions, and the
#                       <path-permission> / <grant-uri-permission> path patterns.
#     package <pkg>     The same, restricted to one package, plus every content://
#                       string mined from the installed APK.
#     apk <file.apk>    Static enumeration from an APK file with no device involved:
#                       merged manifest providers, the FileProvider <paths> resource,
#                       and content:// strings from DEX and resources.
#     probe <authority> Attempt to read every discovered/guessed path under one
#                       authority and classify each response against the five-way
#                       oracle in README section 7.3.
#
#   Everything the probe stage reports is labelled SHELL-READABLE, never
#   "vulnerable". See the reachability note below — it is the whole point of the
#   tool's output format.
#
# WHY IT MATTERS
#   Two reasons this script exists rather than a one-line dumpsys grep.
#
#   1. `exported=true` alone is not a finding, and `exported=true` with a
#      permission is not automatically safe. The verdict depends on the
#      protectionLevel of that permission, which lives in a DIFFERENT part of
#      dumpsys output, in whichever package DECLARED the permission — not
#      necessarily the package using it. This script resolves that link for you,
#      which is the step junior testers skip.
#
#   2. `adb shell` runs as uid 2000 (`shell`) and holds privileges that no
#      third-party application has. A `content query` that succeeds here is NOT
#      proof that an attacker's app can read the provider. Every result this
#      script prints is therefore tagged with its provenance, and the summary
#      ends with the confirmation step you still have to perform. Reporting a
#      shell-only result as a finding is the most common way an Android report
#      gets rejected — see ../README.md section 4.2 and
#      ../../77-UsefulCommands/labs/lab-03-exported-sweep.md.
#
#   A third, smaller reason: the `IllegalArgumentException: Unknown URI` versus
#   `SecurityException` response difference is a path-enumeration oracle. The
#   probe stage is built around it. Reaching the provider's own code and being
#   told your PATH is wrong means you are past the permission check — which is a
#   success, not a failure.
#
# HOW TO RUN
#   ./provider-enum.sh device
#   ./provider-enum.sh device --third-party-only
#   ./provider-enum.sh package com.example.target
#   ./provider-enum.sh apk ./target.apk
#   ./provider-enum.sh probe com.example.target.provider
#   ./provider-enum.sh probe com.example.target.provider --wordlist ./paths.txt
#   ./provider-enum.sh probe com.example.target.provider --write-probe    # DESTRUCTIVE
#
#   Output is plain text on stdout. Redirect it; you will want to diff runs.
#
# REQUIREMENTS
#   adb on PATH, one device connected  (device / package / probe)
#   aapt2 or apktool on PATH           (apk, and the manifest cross-check)
#   unzip, strings                     (apk string mining; optional)
#   No root required. No device-side installation required.
#
# SAFETY
#   Read-only by default. `--write-probe` issues `content insert` against every
#   discovered URI, which MUTATES THE TARGET APP'S DATA. Never use it on a
#   client's production app without that being explicitly in scope, and snapshot
#   the data directory first.
#
# EXIT CODES
#   0 ok · 1 usage · 2 no device · 3 package not installed · 4 missing tool
#
# AUTHORISED TESTING ONLY.

set -uo pipefail

# ------------------------------------------------------------------ constants ---

SCRIPT_NAME="$(basename "$0")"
WRITE_PROBE=0
THIRD_PARTY_ONLY=0
WORDLIST=""

# Paths tried when no wordlist is supplied and nothing was mined from the APK.
# Deliberately short: this is a smoke test, not a brute force. Supply a real
# wordlist with --wordlist for an actual enumeration run.
DEFAULT_PATHS=(
    ""            "/"           "items"       "item"        "data"
    "users"       "user"        "accounts"    "account"     "profile"
    "notes"       "messages"    "contacts"    "settings"    "config"
    "prefs"       "preferences" "session"     "sessions"    "token"
    "tokens"      "auth"        "credentials" "keys"        "files"
    "file"        "docs"        "documents"   "media"       "images"
    "cache"       "db"          "database"    "sync"        "log"
    "logs"        "events"      "history"     "search"      "suggestions"
    "downloads"   "attachments" "export"      "backup"      "debug"
)

# ------------------------------------------------------------------- helpers ---

hr()  { printf '\n== %s %s\n' "$1" "$(printf '=%.0s' $(seq 1 $(( 60 - ${#1} > 0 ? 60 - ${#1} : 3 ))))"; }
sub() { printf '\n-- %s\n' "$1"; }
note(){ printf '   [i] %s\n' "$1"; }
warn(){ printf '   [!] %s\n' "$1"; }

usage() {
    sed -n '3,60p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' not found on PATH" >&2; exit 4; }
}

# adb shell with CRLF stripped. Android's shell emits \r\n; leaving it in breaks
# every downstream grep in ways that waste an hour.
adbsh() { adb shell "$@" 2>&1 | tr -d '\r'; }

require_device() {
    need adb
    if [[ -z "$(adb devices | sed -n '2p')" ]]; then
        echo "error: no device connected (adb devices is empty)" >&2
        exit 2
    fi
}

# ------------------------------------------------------- reachability banner ---
#
# Printed at the top AND the bottom of every run. Repetition is deliberate: this
# is the claim the whole report rests on, and it must not be scrolled past.

banner_top() {
    cat <<'EOF'
###############################################################################
# provider-enum.sh
#
# READ THIS BEFORE YOU BELIEVE ANY LINE BELOW.
#
# This script talks to providers through `adb shell`, which runs as uid 2000
# (`shell`). That identity holds platform privileges an ordinary third-party
# application does NOT hold. Concretely:
#
#   * SHELL-READABLE   means: uid 2000 read data from this provider.
#                      It does NOT mean an attacker's app can.
#   * APP-REACHABLE    is a claim this script CANNOT make. Only a query issued
#                      from an ordinary app uid can establish it — Drozer's
#                      agent, or a sideloaded probe APK.
#
# Every finding must be reproduced from an unprivileged app before it is
# written up. See ../README.md section 4.2 and labs/lab-01-enumerate-and-read.md.
###############################################################################
EOF
}

banner_bottom() {
    cat <<'EOF'

###############################################################################
# NEXT STEP — THE ONE THAT MAKES THIS A FINDING
#
# Everything above ran as uid 2000. To convert an observation into a finding:
#
#   1. Drozer (its agent is an ordinary unprivileged app):
#        dz> run app.provider.info -a <package>
#        dz> run app.provider.query <uri> --vertical
#        dz> run app.provider.read  <uri>
#
#   2. Or a probe APK with NO permissions and a <queries> entry for the target,
#      calling BOTH of these against every URI — they take different code paths
#      inside ContentProvider and can have different permission outcomes:
#
#        getContentResolver().query(uri, null, null, null, null);
#        getContentResolver().openInputStream(uri);
#
#      A provider that denies query() and permits openInputStream() is common,
#      especially for FileProvider-shaped providers. Testing only query() tells
#      you almost nothing about a file-serving provider.
#
#   3. Record BOTH results side by side. "Readable from adb shell" and
#      "readable by an unprivileged third-party app" are different claims with
#      different severities. Conflating them gets the report dismissed.
###############################################################################
EOF
}

# ------------------------------------------------------ permission resolution ---
#
# Resolving a permission name to its protectionLevel is the step that separates a
# real triage from a grep. The permission may be declared by ANY installed
# package, not necessarily the one using it.

resolve_protection_level() {
    local perm="$1"
    [[ -z "$perm" || "$perm" == "null" ]] && { echo "-"; return; }

    local line
    line="$(adbsh "dumpsys package permission $perm" | grep -m1 -oE 'protectionLevel=[^ ]+')"
    if [[ -n "$line" ]]; then
        echo "${line#protectionLevel=}"
        return
    fi

    # Fallback: scan the global permission table. Slower, but works on releases
    # where `dumpsys package permission <name>` is unsupported.
    line="$(adbsh "dumpsys package permissions" \
            | grep -A3 -F "Permission [$perm]" \
            | grep -m1 -oE 'protectionLevel=[^ ]+')"
    if [[ -n "$line" ]]; then
        echo "${line#protectionLevel=}"
    else
        echo "UNDECLARED"
    fi
}

# Turn (exported, permission, protectionLevel) into the verdict from README 5.3.
classify() {
    local exported="$1" rperm="$2" wperm="$3" rlevel="$4" wlevel="$5"

    if [[ "$exported" != "true" ]]; then
        echo "NOT-EXPORTED — not reachable cross-uid (but check sharedUserId)"
        return
    fi

    local verdict=""
    case "$rlevel" in
        "-")                 verdict="READ: OPEN (no permission)" ;;
        *normal*)            verdict="READ: OPEN (normal protection — any app can hold it)" ;;
        *dangerous*)         verdict="READ: WEAK (one user prompt)" ;;
        *signature*)         verdict="READ: guarded by signature perm (check key sharing)" ;;
        UNDECLARED)          verdict="READ: perm '$rperm' is declared by NO installed package — check squatting" ;;
        *)                   verdict="READ: perm=$rperm level=$rlevel — triage by hand" ;;
    esac

    case "$wlevel" in
        "-")                 verdict="$verdict | WRITE: OPEN (no permission)" ;;
        *normal*)            verdict="$verdict | WRITE: OPEN (normal protection)" ;;
        *dangerous*)         verdict="$verdict | WRITE: WEAK" ;;
        *signature*)         verdict="$verdict | WRITE: guarded by signature perm" ;;
        UNDECLARED)          verdict="$verdict | WRITE: perm '$wperm' undeclared" ;;
        *)                   verdict="$verdict | WRITE: perm=$wperm level=$wlevel" ;;
    esac

    echo "$verdict"
}

# ------------------------------------------------------------ device: enumerate ---

dump_provider_record() {
    # $1 = package. Prints one block per provider that package declares.
    local pkg="$1"
    local raw
    raw="$(adbsh "dumpsys package $pkg")"

    # Provider records appear as:  Provider{hash pkg/.ClassName}
    # followed by indented attribute lines. Ranges vary across releases, so take
    # a generous window and filter.
    echo "$raw" | awk '
        /Provider\{/ { inblock=1; print ""; print "  " $0; next }
        inblock && /^[[:space:]]*$/ { inblock=0; next }
        inblock { print "  " $0 }
    ' | grep -E 'Provider\{|authority=|readPermission=|writePermission=|permission=|exported=|grantUriPermissions=|pathPermission|multiprocess=|directBootAware=' \
      || true
}

cmd_device() {
    require_device
    banner_top

    hr "DEVICE"
    for p in ro.build.version.release ro.build.version.sdk ro.build.version.security_patch; do
        printf '   %-34s %s\n' "$p" "$(adbsh "getprop $p")"
    done
    printf '   %-34s %s\n' "shell uid" "$(adbsh id | tr -d '\n')"
    note "Android 11+ (API 30) restricts package visibility for APPS, not for the shell."
    note "This enumeration is therefore MORE complete than an attacker app's would be."

    hr "ALL PROVIDERS REGISTERED ON THE DEVICE"
    note "Source: dumpsys package providers (what PackageManagerService actually parsed)."
    note "Trust this over any decompiler output."
    adbsh "dumpsys package providers" | sed 's/^/   /'

    hr "PER-PACKAGE TRIAGE"

    local pkglist
    if [[ "$THIRD_PARTY_ONLY" -eq 1 ]]; then
        note "Restricted to third-party packages (pm list packages -3)."
        pkglist="$(adbsh "pm list packages -3" | sed 's/package://')"
    else
        pkglist="$(adbsh "pm list packages" | sed 's/package://')"
    fi

    local total=0 exported_count=0 open_count=0
    local pkg
    for pkg in $pkglist; do
        [[ -z "$pkg" ]] && continue
        local block
        block="$(dump_provider_record "$pkg")"
        [[ -z "$(echo "$block" | grep -E 'authority=')" ]] && continue

        sub "PACKAGE $pkg"
        echo "$block"

        # Parse each authority/exported/permission triple out of the block.
        local auths
        auths="$(echo "$block" | grep -oE 'authority=[^ ]+' | sed 's/authority=//' | tr ';' '\n' | sort -u)"
        local a
        for a in $auths; do
            [[ -z "$a" ]] && continue
            total=$((total + 1))

            local exported rperm wperm gperm rlevel wlevel
            exported="$(echo "$block" | grep -m1 -oE 'exported=(true|false)' | sed 's/exported=//')"
            [[ -z "$exported" ]] && exported="unknown"
            rperm="$(echo "$block" | grep -m1 -oE 'readPermission=[^ ]+' | sed 's/readPermission=//')"
            wperm="$(echo "$block" | grep -m1 -oE 'writePermission=[^ ]+' | sed 's/writePermission=//')"
            gperm="$(echo "$block" | grep -m1 -oE 'grantUriPermissions=[^ ]+' | sed 's/grantUriPermissions=//')"

            # android:permission is the shorthand; read/write override it independently.
            local shorthand
            shorthand="$(echo "$block" | grep -m1 -oE '(^|[^a-zA-Z])permission=[^ ]+' | sed 's/.*permission=//')"
            [[ -z "$rperm" ]] && rperm="$shorthand"
            [[ -z "$wperm" ]] && wperm="$shorthand"

            rlevel="$(resolve_protection_level "$rperm")"
            wlevel="$(resolve_protection_level "$wperm")"

            printf '\n   authority            : %s\n' "$a"
            printf '   exported             : %s\n' "$exported"
            printf '   readPermission       : %s (protectionLevel=%s)\n'  "${rperm:--}" "$rlevel"
            printf '   writePermission      : %s (protectionLevel=%s)\n'  "${wperm:--}" "$wlevel"
            printf '   grantUriPermissions  : %s\n' "${gperm:--}"
            printf '   VERDICT              : %s\n' "$(classify "$exported" "$rperm" "$wperm" "$rlevel" "$wlevel")"

            if [[ "$exported" == "true" ]]; then
                exported_count=$((exported_count + 1))
                if [[ "$rlevel" == "-" || "$rlevel" == *normal* ]]; then
                    open_count=$((open_count + 1))
                    printf '   >>> WORTH PROBING     : ./%s probe %s\n' "$SCRIPT_NAME" "$a"
                fi
            fi
        done
    done

    hr "SUMMARY"
    printf '   authorities seen              : %s\n' "$total"
    printf '   exported                      : %s\n' "$exported_count"
    printf '   exported + open/normal perm   : %s   <-- your working list\n' "$open_count"
    note "grantUriPermissions=true on ANY of these makes it a target for URI-grant"
    note "laundering even if it is otherwise guarded. See README section 5.4."

    banner_bottom
}

# ---------------------------------------------------------------- package mode ---

cmd_package() {
    local pkg="$1"
    require_device
    banner_top

    if [[ -z "$(adbsh "pm path $pkg" | grep -m1 package:)" ]]; then
        echo "error: package $pkg is not installed" >&2
        exit 3
    fi

    hr "PACKAGE $pkg"
    adbsh "dumpsys package $pkg" | grep -E 'versionName|targetSdk|minSdk|sharedUser' | sed 's/^/   /'
    note "targetSdk < 17 means android:exported defaulted to TRUE for providers."
    note "sharedUserId present means every app in that group bypasses provider"
    note "permissions entirely (same-uid short circuit in checkComponentPermission)."

    hr "PROVIDER RECORDS AS PARSED BY PackageManagerService"
    dump_provider_record "$pkg"

    hr "PROVIDER RESOLVER TABLE"
    adbsh "dumpsys package $pkg" | sed -n '/Provider Resolver Table/,/^ *$/p' | sed 's/^/   /'

    hr "PATH PERMISSIONS AND GRANT RULES"
    note "These do not always survive into dumpsys output on every release. If this"
    note "section is empty, read them out of the APK instead: ./$SCRIPT_NAME apk <file>"
    adbsh "dumpsys package $pkg" | grep -iE 'pathPermission|PathPermission|grant-uri|GrantUri' | sed 's/^/   /'

    hr "content:// STRINGS MINED FROM THE INSTALLED APK"
    local apk
    apk="$(adbsh "pm path $pkg" | head -1 | sed 's/package://')"
    note "APK on device: $apk"
    if command -v unzip >/dev/null 2>&1 && command -v strings >/dev/null 2>&1; then
        local tmp
        tmp="$(mktemp -d 2>/dev/null || echo "/tmp/provenum.$$")"
        mkdir -p "$tmp"
        if adb pull "$apk" "$tmp/target.apk" >/dev/null 2>&1; then
            (cd "$tmp" && unzip -o -q target.apk 'classes*.dex' 'res/*' 2>/dev/null) || true
            strings -a "$tmp"/*.dex 2>/dev/null \
                | grep -aoE 'content://[A-Za-z0-9._~%/#*+-]+' | sort -u | sed 's/^/   /'
            note "Also mine the resources — authorities frequently live in strings.xml:"
            grep -rhoaE 'content://[A-Za-z0-9._~%/#*+-]+' "$tmp/res" 2>/dev/null \
                | sort -u | sed 's/^/   /'
            rm -rf "$tmp"
        else
            warn "adb pull failed — skipping string mining."
        fi
    else
        warn "unzip/strings unavailable — skipping string mining."
        note "Equivalent: drozer 'run app.provider.finduri $pkg'"
    fi
    note "This misses runtime-constructed URIs (Uri.Builder, withAppendedPath)."
    note "Hook android.content.UriMatcher.addURI with Frida to catch those."

    hr "SUGGESTED NEXT COMMANDS"
    local auths
    auths="$(adbsh "dumpsys package $pkg" | grep -oE 'authority=[^ ]+' | sed 's/authority=//' | tr ';' '\n' | sort -u)"
    local a
    for a in $auths; do
        [[ -z "$a" ]] && continue
        printf '   ./%s probe %s\n' "$SCRIPT_NAME" "$a"
    done

    banner_bottom
}

# -------------------------------------------------------------------- apk mode ---

cmd_apk() {
    local apk="$1"
    [[ -f "$apk" ]] || { echo "error: $apk not found" >&2; exit 1; }

    banner_top
    hr "STATIC ENUMERATION — $apk"
    note "No device involved. This reads the MERGED manifest that actually ships,"
    note "which is the only manifest that matters. Library providers appear here"
    note "and do not appear in app/src/main/AndroidManifest.xml."

    local have_aapt2=0 have_apktool=0
    command -v aapt2   >/dev/null 2>&1 && have_aapt2=1
    command -v apktool >/dev/null 2>&1 && have_apktool=1

    if [[ $have_aapt2 -eq 0 && $have_apktool -eq 0 ]]; then
        echo "error: need aapt2 or apktool on PATH" >&2
        exit 4
    fi

    if [[ $have_aapt2 -eq 1 ]]; then
        sub "aapt2 dump xmltree — the raw binary XML, independently parsed"
        note "(type 0x12)0xffffffff means true; (type 0x12)0x0 means false."
        aapt2 dump xmltree "$apk" --file AndroidManifest.xml 2>/dev/null \
            | awk '/E: provider/{p=1} p{print "   " $0} /^ *E: [a-z]/{ if ($0 !~ /provider/) p=0 }' \
            | head -400
    fi

    if [[ $have_apktool -eq 1 ]]; then
        local work
        work="$(mktemp -d 2>/dev/null || echo "/tmp/provenum-apk.$$")"
        mkdir -p "$work"
        apktool d -f "$apk" -o "$work/out" >/dev/null 2>&1

        sub "Decoded <provider> declarations"
        grep -A12 '<provider' "$work/out/AndroidManifest.xml" 2>/dev/null | sed 's/^/   /'

        sub "FileProvider <paths> resources — where the real configuration lives"
        note "The manifest only POINTS at this file via <meta-data>. Open it."
        local f
        for f in "$work"/out/res/xml/*.xml; do
            [[ -e "$f" ]] || continue
            if grep -q '<paths' "$f" 2>/dev/null; then
                echo "   ---- $f"
                sed 's/^/   /' "$f"
                if grep -q 'root-path' "$f"; then
                    warn "root-path PRESENT in $f — this is a finding on its own."
                    warn "See ../examples/file_paths_annotated.xml and README section 3.8."
                fi
            fi
        done

        sub "Every content:// string in the decoded tree"
        grep -rhoaE 'content://[A-Za-z0-9._~%/#*+-]+' "$work/out" 2>/dev/null \
            | sort -u | sed 's/^/   /'

        sub "Grep signposts inside the manifest"
        grep -nE 'grantUriPermissions|path-permission|grant-uri-permission|sharedUserId|targetSdkVersion' \
            "$work/out/AndroidManifest.xml" 2>/dev/null | sed 's/^/   /'

        rm -rf "$work"
    fi

    hr "WHAT THIS MODE CANNOT TELL YOU"
    note "Whether the provider is REACHABLE. exported=true in a manifest is a"
    note "declaration; reachability is a runtime property that also depends on the"
    note "permission's protectionLevel as resolved on the actual device, on"
    note "sharedUserId, and on whether the permission is declared at all."
    note "Run:  ./$SCRIPT_NAME package <pkg>   with the app installed."

    banner_bottom
}

# ------------------------------------------------------------------ probe mode ---
#
# The five-way oracle from README section 7.3, implemented as a classifier.

classify_response() {
    local out="$1"

    if   echo "$out" | grep -q "not exported from"; then
        echo "NOT-EXPORTED       | provider exists, unreachable cross-uid"
    elif echo "$out" | grep -qi "Permission Denial"; then
        local perm
        perm="$(echo "$out" | grep -oE 'requires [^ ]+( or [^ ]+)?' | head -1)"
        echo "PERMISSION-DENIED  | reachable but guarded — ${perm:-permission unnamed}"
    elif echo "$out" | grep -qi "IllegalArgumentException.*Unknown URI\|Unknown URI"; then
        echo "PAST-THE-CHECK     | provider CODE ran and rejected the PATH ONLY <<< probe succeeded"
    elif echo "$out" | grep -qi "Unable to resolve content provider\|Could not find provider"; then
        echo "NO-SUCH-AUTHORITY  | wrong authority, or hidden by package visibility"
    elif echo "$out" | grep -qi "No result found\|^$"; then
        echo "EMPTY              | reached the data, zero matching rows"
    elif echo "$out" | grep -qi "Row:"; then
        echo "SHELL-READABLE     | DATA RETURNED to uid 2000 — confirm from an app"
    elif echo "$out" | grep -qi "SQLiteException\|no such table\|no such column\|syntax error"; then
        echo "SQL-ERROR-LEAK     | raw SQLite error surfaced — injection candidate"
    elif echo "$out" | grep -qi "Exception"; then
        echo "OTHER-EXCEPTION    | read it by hand, it may be informative"
    else
        echo "UNCLASSIFIED       | read the raw output"
    fi
}

probe_uri() {
    local uri="$1"
    local out cls

    # query() — the read path.
    out="$(adbsh "content query --uri '$uri' 2>&1" | head -20)"
    cls="$(classify_response "$out")"
    printf '   query      %-70s %s\n' "$uri" "$cls"
    if echo "$cls" | grep -q "SHELL-READABLE\|SQL-ERROR-LEAK\|PAST-THE-CHECK"; then
        echo "$out" | head -6 | sed 's/^/                 | /'
    fi

    # getType() — deliberately unprotected by the framework. A free reachability
    # probe that never triggers a permission error. If this returns a type while
    # query() is denied, the authority certainly exists.
    out="$(adbsh "content gettype --uri '$uri' 2>&1" | head -5)"
    if echo "$out" | grep -qiE 'Result:|vnd\.|/'; then
        printf '   gettype    %-70s TYPE: %s\n' "$uri" "$(echo "$out" | tr -d '\n' | cut -c1-60)"
    fi

    # openFile() — a DIFFERENT code path from query(), with a DIFFERENT permission
    # outcome. A provider can deny query and permit read. Never test only one.
    out="$(adbsh "content read --uri '$uri' 2>&1 | head -c 200")"
    if echo "$out" | grep -qiE 'Exception|Error'; then
        cls="$(classify_response "$out")"
        printf '   read       %-70s %s\n' "$uri" "$cls"
    elif [[ -n "$out" ]]; then
        printf '   read       %-70s SHELL-READABLE  | %s bytes of file content returned\n' \
               "$uri" "$(printf '%s' "$out" | wc -c | tr -d ' ')"
        printf '                 | first bytes: %s\n' "$(printf '%s' "$out" | head -c 80 | tr -d '\0' | tr '\n' ' ')"
    fi

    if [[ "$WRITE_PROBE" -eq 1 ]]; then
        out="$(adbsh "content insert --uri '$uri' --bind probe_marker:s:provider-enum 2>&1" | head -5)"
        cls="$(classify_response "$out")"
        printf '   insert     %-70s %s\n' "$uri" "$cls"
    fi
}

cmd_probe() {
    local auth="$1"
    require_device
    banner_top

    hr "PROBING content://$auth"
    warn "Everything below runs as uid 2000. Nothing below is a finding yet."

    sub "Step 1 — does the authority resolve at all?"
    local base="content://$auth"
    local out
    out="$(adbsh "content query --uri '$base' 2>&1" | head -10)"
    printf '   %s\n' "$(classify_response "$out")"
    echo "$out" | sed 's/^/     | /' | head -8

    sub "Step 2 — call() with no method name, to see whether call() is implemented"
    note "call() gets NO automatic permission check. If the provider is exported"
    note "with no permission, this surface is completely open. See README 5.5."
    out="$(adbsh "content call --uri '$base' --method __enum_probe__ 2>&1" | head -8)"
    echo "$out" | sed 's/^/     | /'
    if echo "$out" | grep -qi "IllegalArgumentException.*method\|Unsupported method\|Unknown method"; then
        note "The provider THREW on an unknown method. It implements call() and"
        note "distinguishes known from unknown names — that is a working oracle."
        note "Enumerate it: python3 ./provider-call-fuzz.py --authority $auth --mode call"
    elif echo "$out" | grep -qi "Result: null\|^$"; then
        note "Null on an unknown method. Either call() is unimplemented, or it"
        note "returns null for unknown names (which is the common default and"
        note "makes the oracle weaker, not absent). Fuzz it anyway."
    fi

    sub "Step 3 — path enumeration"
    local paths=()
    if [[ -n "$WORDLIST" && -f "$WORDLIST" ]]; then
        note "Wordlist: $WORDLIST"
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            paths+=("$line")
        done < "$WORDLIST"
    else
        note "No wordlist supplied — using the built-in smoke-test list."
        note "For a real engagement, mine paths first:"
        note "  ./$SCRIPT_NAME package <pkg>        (strings from the APK)"
        note "  drozer: run app.provider.finduri <pkg>"
        note "  frida: hook android.content.UriMatcher.addURI and launch the app"
        paths=("${DEFAULT_PATHS[@]}")
    fi

    printf '\n   %-10s %-70s %s\n' "OP" "URI" "CLASSIFICATION"
    printf '   %s\n' "$(printf -- '-%.0s' $(seq 1 110))"

    local p uri
    for p in "${paths[@]}"; do
        if [[ -z "$p" ]]; then uri="content://$auth"; else uri="content://$auth/${p#/}"; fi
        probe_uri "$uri"
    done

    sub "Step 4 — the four injection points, one marker each"
    note "A marker that comes back in an error message, or changes the result set,"
    note "is an injection. Test ALL FOUR: scanners typically test only --where."
    local target="content://$auth"
    if [[ -n "${paths[0]:-}" ]]; then target="content://$auth/${paths[0]#/}"; fi

    printf '\n   projection : '
    adbsh "content query --uri '$target' --projection \"PROVENUM_MARKER_1\" 2>&1" | head -3 | tr '\n' ' ' ; echo
    printf '   selection  : '
    adbsh "content query --uri '$target' --where \"PROVENUM_MARKER_2='x'\" 2>&1" | head -3 | tr '\n' ' ' ; echo
    printf '   sortOrder  : '
    adbsh "content query --uri '$target' --sort \"PROVENUM_MARKER_3\" 2>&1" | head -3 | tr '\n' ' ' ; echo
    printf '   uri path   : '
    adbsh "content query --uri \"content://$auth/PROVENUM_MARKER_4\" 2>&1" | head -3 | tr '\n' ' ' ; echo

    note "If a marker appears verbatim in a SQLite error ('no such column:"
    note "PROVENUM_MARKER_1'), that parameter is concatenated into raw SQL and is"
    note "injectable. Follow up with ./provider-call-fuzz.py or by hand."

    sub "Step 5 — traversal smoke test against openFile"
    note "openFile() takes a DIFFERENT code path from query() and can have a"
    note "DIFFERENT permission outcome. Always test both."
    local trav
    for trav in "..%2F..%2Fdatabases" "%2Fproc%2Fself%2Fmaps" "..%2F..%2Fshared_prefs"; do
        printf '   read %-60s ' "content://$auth/$trav"
        adbsh "content read --uri 'content://$auth/$trav' 2>&1 | head -c 120" | tr '\n' ' '
        echo
    done

    banner_bottom
}

# ---------------------------------------------------------------------- main ---

[[ $# -lt 1 ]] && usage
SUBCMD="$1"; shift

# Parse trailing flags out of the argument list.
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --write-probe)      WRITE_PROBE=1 ;;
        --third-party-only) THIRD_PARTY_ONLY=1 ;;
        --wordlist)         shift; WORDLIST="${1:-}" ;;
        -h|--help)          usage ;;
        *)                  ARGS+=("$1") ;;
    esac
    shift
done

case "$SUBCMD" in
    device)  cmd_device ;;
    package) [[ ${#ARGS[@]} -lt 1 ]] && usage; cmd_package "${ARGS[0]}" ;;
    apk)     [[ ${#ARGS[@]} -lt 1 ]] && usage; cmd_apk     "${ARGS[0]}" ;;
    probe)   [[ ${#ARGS[@]} -lt 1 ]] && usage; cmd_probe   "${ARGS[0]}" ;;
    *)       usage ;;
esac
