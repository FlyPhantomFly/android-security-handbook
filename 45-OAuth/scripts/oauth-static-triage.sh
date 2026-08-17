#!/usr/bin/env bash
#
# oauth-static-triage.sh — answer the OAuth questions about an APK that can be answered without
# running it, in one pass, in the order a real engagement asks them.
#
# WHAT IT DOES
#   1. Unpacks the APK with apktool and decompiles it with jadx.
#   2. Reports the redirect mechanism: custom scheme(s) vs App Link(s), and autoVerify state.
#   3. Reports the callback activity and whether it is exported.
#   4. Searches for dead grants (ROPC, implicit) and for an embedded client_secret.
#   5. Searches for a WebView-based authorisation flow.
#   6. Detects AppAuth and other OAuth libraries.
#   7. Extracts every OAuth-looking endpoint URL.
#   8. Checks allowBackup and the network security config, because they decide what happens to the
#      tokens afterwards.
#   9. Checks native libraries and cross-platform bundles, because the flow may not be in the DEX.
#  10. Prints the exact follow-up commands that need a device, since static analysis cannot answer
#      the question that actually matters.
#
# USAGE
#   host $ ./oauth-static-triage.sh target.apk
#   host $ ./oauth-static-triage.sh target.apk /tmp/workdir
#
# REQUIREMENTS
#   apktool, jadx, unzip, grep, and optionally aapt2. Missing tools degrade gracefully.
#
# LIMITS — READ THIS
#   Nothing here can tell you whether the SERVER enforces PKCE, which is the finding that matters
#   most. Static analysis of a mobile app cannot see the token endpoint's behaviour. Use this to
#   build the target list, then go to labs 02 and 03.
#
# Chapter 45 — OAuth 2.0 and OpenID Connect on Android, section 8
#

set -uo pipefail

APK="${1:-}"
WORK="${2:-./oauth-triage-$(date +%s)}"

if [ -z "$APK" ] || [ ! -f "$APK" ]; then
    echo "usage: $0 <target.apk> [workdir]" >&2
    exit 1
fi

# --------------------------------------------------------------------------- #
# Presentation helpers
# --------------------------------------------------------------------------- #
if [ -t 1 ]; then
    R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; B=$'\033[1m'; N=$'\033[0m'; D=$'\033[90m'
else
    R=''; Y=''; G=''; B=''; N=''; D=''
fi

section() { printf '\n%s\n%s  %s%s\n%s\n' "$(printf '=%.0s' {1..76})" "$B" "$1" "$N" \
                  "$(printf '=%.0s' {1..76})"; }
note()    { printf '  %s%s%s\n' "$D" "$1" "$N"; }
bad()     { printf '  %s[!!]%s %s\n' "$R" "$N" "$1"; }
warn()    { printf '  %s[??]%s %s\n' "$Y" "$N" "$1"; }
good()    { printf '  %s[ok]%s %s\n' "$G" "$N" "$1"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------- #
# 0. Unpack
# --------------------------------------------------------------------------- #
section "0. Unpacking $APK"
mkdir -p "$WORK"

if have apktool; then
    apktool d -f -o "$WORK/apktool" "$APK" >/dev/null 2>&1 \
        && good "apktool -> $WORK/apktool" \
        || warn "apktool failed; falling back to unzip"
else
    warn "apktool not found — manifest will be binary XML and less readable"
fi

if [ ! -d "$WORK/apktool" ]; then
    mkdir -p "$WORK/raw" && unzip -o -q "$APK" -d "$WORK/raw" && good "unzip -> $WORK/raw"
fi

if have jadx; then
    note "running jadx (this is the slow step)..."
    jadx -d "$WORK/jadx" --no-debug-info -q "$APK" >/dev/null 2>&1
    good "jadx -> $WORK/jadx"
else
    warn "jadx not found — source searches will be skipped"
fi

MANIFEST="$WORK/apktool/AndroidManifest.xml"
[ -f "$MANIFEST" ] || MANIFEST="$WORK/raw/AndroidManifest.xml"
SRC="$WORK/jadx/sources"
RES="$WORK/apktool/res"

PKG=$(grep -o 'package="[^"]*"' "$MANIFEST" 2>/dev/null | head -1 | cut -d'"' -f2)
[ -n "${PKG:-}" ] && note "package: $PKG"

# --------------------------------------------------------------------------- #
# 1. The redirect mechanism — the fastest source of truth
# --------------------------------------------------------------------------- #
section "1. Redirect mechanism (manifest)"

if [ -f "$MANIFEST" ]; then
    CUSTOM=$(grep -o 'android:scheme="[^"]*"' "$MANIFEST" \
             | cut -d'"' -f2 | sort -u | grep -vE '^(https?|file|content|package|market)$' || true)
    if [ -n "$CUSTOM" ]; then
        bad "custom URI scheme(s) declared — Android enforces no uniqueness on these:"
        echo "$CUSTOM" | while read -r s; do printf '        %s://\n' "$s"; done
        note "Any installed app may declare the same scheme and receive the authorisation code."
        note "Severity depends entirely on server-side PKCE enforcement. See lab 03."
    else
        good "no custom schemes declared"
    fi

    if grep -q 'android:autoVerify="true"' "$MANIFEST" 2>/dev/null; then
        warn "android:autoVerify=\"true\" is declared"
        note "That is the app ASKING for verification. It is not verification."
        note "Confirm on a device:  adb shell pm get-app-links ${PKG:-<pkg>}"
        grep -B2 -A8 'autoVerify="true"' "$MANIFEST" | grep -E 'android:(host|path|scheme)' \
            | sed 's/^/        /' | sort -u
    else
        note "no autoVerify declared — no App Links attempted"
    fi

    echo
    note "activities handling BROWSABLE VIEW intents (candidate callback activities):"
    grep -B12 'android.intent.category.BROWSABLE' "$MANIFEST" \
        | grep -o 'android:name="[^"]*Activity[^"]*"' | cut -d'"' -f2 | sort -u \
        | sed 's/^/        /'
else
    warn "no readable manifest"
fi

# --------------------------------------------------------------------------- #
# 2. Storage and transport posture
# --------------------------------------------------------------------------- #
section "2. Storage and transport posture"

if [ -f "$MANIFEST" ]; then
    if grep -q 'android:allowBackup="true"' "$MANIFEST"; then
        bad "android:allowBackup=\"true\" — tokens in app storage are extractable via adb backup"
    elif grep -q 'android:allowBackup="false"' "$MANIFEST"; then
        good "android:allowBackup=\"false\""
    else
        warn "allowBackup not set — defaults to true below API 31 targets"
    fi

    NSC=$(grep -o 'android:networkSecurityConfig="[^"]*"' "$MANIFEST" | cut -d'"' -f2 || true)
    if [ -n "${NSC:-}" ]; then
        note "network security config: $NSC"
        NSC_FILE=$(find "$WORK" -name "$(basename "${NSC##*/}").xml" 2>/dev/null | head -1)
        if [ -n "${NSC_FILE:-}" ]; then
            grep -E 'cleartextTrafficPermitted|pin-set|<domain|user|system' "$NSC_FILE" \
                | sed 's/^/        /'
        fi
    else
        note "no network security config — platform defaults apply"
    fi

    grep -q 'android:usesCleartextTraffic="true"' "$MANIFEST" \
        && bad "usesCleartextTraffic=\"true\" — the token exchange may travel in the clear"
fi

# --------------------------------------------------------------------------- #
# 3. Dead grants and embedded secrets
# --------------------------------------------------------------------------- #
section "3. Dead grants and embedded secrets"

search() {  # search <pattern> <label>
    local pat="$1" label="$2" hits=""
    [ -d "$SRC" ] && hits=$(grep -rn --binary-files=without-match -E "$pat" "$SRC" 2>/dev/null | head -12)
    if [ -z "$hits" ] && [ -d "$RES" ]; then
        hits=$(grep -rn --binary-files=without-match -E "$pat" "$RES" 2>/dev/null | head -12)
    fi
    if [ -n "$hits" ]; then
        bad "$label"
        echo "$hits" | sed "s|$WORK/||" | sed 's/^/        /'
        return 0
    fi
    return 1
}

search 'grant_type["'"'"'=][[:space:]]*=?[[:space:]]*["'"'"']?password' \
       "ROPC (password) grant — the app handles the user's IdP password" || \
    good "no ROPC grant string found"

search 'response_type["'"'"'=][[:space:]]*=?[[:space:]]*["'"'"']?(token|id_token token)' \
       "implicit grant — access token returned in the URL fragment" || \
    good "no implicit grant string found"

search 'client_secret|CLIENT_SECRET|clientSecret' \
       "client_secret referenced — a mobile app cannot hold a secret" || \
    good "no client_secret reference found"

search 'grant_type["'"'"'=][[:space:]]*=?[[:space:]]*["'"'"']?client_credentials' \
       "client_credentials grant from a mobile app — implies an embedded secret" || true

# --------------------------------------------------------------------------- #
# 4. PKCE and state — client-side only
# --------------------------------------------------------------------------- #
section "4. PKCE and state (client-side evidence only)"

note "Protocol parameter names survive every obfuscator, because they go on the wire."
note "They are the anchor from which everything else is found."
echo

for p in code_challenge code_challenge_method code_verifier state nonce; do
    n=0
    [ -d "$SRC" ] && n=$(grep -rl --binary-files=without-match "$p" "$SRC" 2>/dev/null | wc -l | tr -d ' ')
    printf '  %-24s referenced in %s file(s)\n' "$p" "$n"
done

if [ -d "$SRC" ] && grep -rq 'S256' "$SRC" 2>/dev/null; then
    good "S256 referenced"
else
    warn "no S256 string found — check for `plain`, or for a library that hides it"
fi

if [ -d "$SRC" ] && grep -rq '"plain"' "$SRC" 2>/dev/null; then
    warn "the literal \"plain\" appears — check whether it is a code_challenge_method"
fi

if [ -d "$SRC" ]; then
    if grep -rq 'new Random(\|Math\.random\|System\.currentTimeMillis()' "$SRC" 2>/dev/null; then
        note "non-SecureRandom sources present somewhere in the app; check whether any feed"
        note "state or code_verifier generation — a predictable nonce is not a nonce"
    fi
fi

printf '\n  %sSTATIC ANALYSIS CANNOT ANSWER THE QUESTION THAT MATTERS.%s\n' "$Y" "$N"
note "Whether the SERVER enforces PKCE is invisible from here. Go to lab 02."

# --------------------------------------------------------------------------- #
# 5. WebView-based flow
# --------------------------------------------------------------------------- #
section "5. Embedded user agent (WebView) — a finding in itself"

if [ -d "$SRC" ]; then
    WV=$(grep -rn --binary-files=without-match 'loadUrl' "$SRC" 2>/dev/null \
         | grep -iE 'authorize|oauth|openid|/auth\?|signin|sso' | head -10)
    if [ -n "$WV" ]; then
        bad "a WebView appears to load an authorisation endpoint"
        echo "$WV" | sed "s|$WORK/||" | sed 's/^/        /'
        note "RFC 8252 s8.12 prohibits embedded user agents. Confirm dynamically:"
        note "  frida -U -f ${PKG:-<pkg>} -l detect-webview-oauth.js"
    else
        good "no WebView loading an authorisation endpoint found statically"
        note "Confirm dynamically anyway — the URL may be built at runtime."
    fi

    grep -rl --binary-files=without-match 'addJavascriptInterface' "$SRC" 2>/dev/null | head -5 \
        | while read -r f; do warn "addJavascriptInterface in ${f#"$WORK"/}"; done
    grep -rl --binary-files=without-match 'setJavaScriptEnabled(true)' "$SRC" 2>/dev/null | head -5 \
        | while read -r f; do note "setJavaScriptEnabled(true) in ${f#"$WORK"/}"; done
else
    warn "no decompiled sources — skipping"
fi

# --------------------------------------------------------------------------- #
# 6. Libraries
# --------------------------------------------------------------------------- #
section "6. OAuth libraries in use"

if [ -d "$WORK/jadx" ]; then
    for lib in "net/openid/appauth:AppAuth-Android (certified RFC 8252 client)" \
               "com/google/android/gms/auth:Google Play Services auth" \
               "androidx/browser/customtabs:AndroidX Custom Tabs" \
               "com/microsoft/identity:MSAL (Microsoft)" \
               "com/auth0:Auth0 SDK" \
               "com/okta:Okta SDK" \
               "com/nimbusds:Nimbus JOSE+JWT" \
               "com/auth0/jwt:java-jwt"; do
        path="${lib%%:*}"; label="${lib#*:}"
        [ -d "$WORK/jadx/sources/$path" ] && good "$label"
    done
    [ -d "$WORK/jadx/sources/net/openid/appauth" ] && \
        note "AppAuth makes the CLIENT correct. It cannot make the server enforce PKCE, verify"
    [ -d "$WORK/jadx/sources/net/openid/appauth" ] && \
        note "your App Link, or check aud at your backend. Keep testing."
fi

# --------------------------------------------------------------------------- #
# 7. Endpoints
# --------------------------------------------------------------------------- #
section "7. OAuth endpoints found"

{
    [ -d "$SRC" ] && grep -rhoE 'https://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+' "$SRC" 2>/dev/null
    [ -d "$RES" ] && grep -rhoE 'https://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+' "$RES" 2>/dev/null
} | grep -iE 'oauth|authorize|/token|openid|/auth|connect/|well-known|jwks|realms' \
  | sed 's/["'"'"'<].*$//' | sort -u | head -40 | sed 's/^/        /'

echo
note "For each distinct host, fetch the discovery document — it is the cheapest evidence:"
note "  curl -s https://HOST/.well-known/openid-configuration | jq"

# --------------------------------------------------------------------------- #
# 8. Native and cross-platform
# --------------------------------------------------------------------------- #
section "8. Native libraries and cross-platform runtimes"

LIBDIR="$WORK/apktool/lib"; [ -d "$LIBDIR" ] || LIBDIR="$WORK/raw/lib"
ASSETS="$WORK/apktool/assets"; [ -d "$ASSETS" ] || ASSETS="$WORK/raw/assets"

if [ -d "$LIBDIR" ]; then
    find "$LIBDIR" -name '*.so' 2>/dev/null | sed "s|$WORK/||" | head -20 | sed 's/^/        /'
    if find "$LIBDIR" -name 'libflutter.so' 2>/dev/null | grep -q .; then
        warn "Flutter app — the OAuth flow may be entirely in Dart, invisible to jadx"
    fi
    for so in $(find "$LIBDIR" -name '*.so' 2>/dev/null | head -10); do
        if strings "$so" 2>/dev/null | grep -qiE 'code_challenge|client_secret|grant_type'; then
            bad "OAuth strings inside $(basename "$so") — the flow may run in native code"
        fi
    done
fi

if [ -d "$ASSETS" ]; then
    ls "$ASSETS" 2>/dev/null | grep -iE 'bundle|flutter|dll|unity|www' | head \
        | while read -r a; do warn "cross-platform asset: $a — check it separately"; done
    if [ -f "$ASSETS/index.android.bundle" ]; then
        warn "React Native bundle present"
        grep -oE 'code_challenge|client_secret|grant_type=[a-z_]+' \
            "$ASSETS/index.android.bundle" 2>/dev/null | sort -u | head | sed 's/^/        /'
    fi
fi

# --------------------------------------------------------------------------- #
# 9. What to do next
# --------------------------------------------------------------------------- #
section "9. Follow-up that requires a device"

cat <<EOF
  These answer the questions static analysis cannot.

  # is the App Link actually verified, or only declared?
  adb shell pm get-app-links ${PKG:-<pkg>}

  # who else claims the redirect scheme?
  adb shell cmd package query-activities -a android.intent.action.VIEW -d "<scheme>://<host>"

  # fire a callback by hand
  adb shell am start -a android.intent.action.VIEW -d "<scheme>://<host>?code=X&state=Y"

  # trace the whole flow, get the code_verifier
  frida -U -f ${PKG:-<pkg>} -l oauth-flow-tracer.js

  # is it a WebView flow?
  frida -U -f ${PKG:-<pkg>} -l detect-webview-oauth.js

  # server posture in one request
  curl -s https://<idp-host>/.well-known/openid-configuration | jq

  # >>> THE TEST THAT MATTERS <<<
  # capture a FRESH authorisation code, then exchange it with NO code_verifier.
  # A 200 with tokens is a Critical finding. See lab 02.
  curl -s -X POST https://<idp>/token -d grant_type=authorization_code \\
       -d code="\$CODE" -d redirect_uri="<ruri>" -d client_id="<cid>"

EOF

section "Done"
note "workdir: $WORK"
