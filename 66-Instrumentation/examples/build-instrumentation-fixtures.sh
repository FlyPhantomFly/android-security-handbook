#!/usr/bin/env bash
# examples/build-instrumentation-fixtures.sh
#
# PURPOSE
#   Build chapter 66's instrumentation fixtures with nothing but the Android SDK
#   build-tools and a JDK. No Gradle, no Android Studio, no network, no
#   androidx.test, no JUnit. Five APKs come out, and the differences between them
#   are exactly the variables the chapter measures:
#
#     vault-debuggable.apk    target app, android:debuggable="true"
#     vault-release.apk       the SAME sources, debuggable absent
#     probe-sigA.apk          test APK, signed with key A (same key as the target)
#     probe-sigB.apk          the SAME test APK, signed with key B
#     probe-testonly.apk      key A, plus android:testOnly="true"
#
#   Four of the five differ from another one in exactly ONE bit. That is what
#   makes "does instrumentation require a debuggable target?" and "must the
#   signatures match?" measurable instead of arguable.
#
# USAGE
#   # host -- build all five into $OUTDIR
#   ./build-instrumentation-fixtures.sh
#
#   # host -- build, then install the debuggable target + probe-sigA
#   ./build-instrumentation-fixtures.sh --install
#
#   # host -- put artefacts somewhere specific
#   OUTDIR=/tmp/ch66 ./build-instrumentation-fixtures.sh
#
#   # host -- remove both packages from the device
#   ./build-instrumentation-fixtures.sh --uninstall
#
# WAS THIS SCRIPT EXECUTED?
#   YES. Run on 2026-08-16 against the AVD sdk_gphone16k_x86_64 (Android 15 /
#   API 35, x86_64, userdebug) with build-tools 35.0.1, platform android-35 and
#   JDK 24.0.2 under Git Bash on Windows 11. All five APKs built; the install and
#   instrument matrix in scripts/am-instrument-matrix.sh was driven from them.
#
# REQUIREMENTS
#   * ANDROID_HOME (or ANDROID_SDK_ROOT, or the SDK in a standard location) with
#     build-tools providing aapt2, d8, zipalign, apksigner, and one platform
#     android.jar.
#   * A JDK with javac and keytool. javac 24 works; --release 8 is passed.
#   * python3 for the zip step (the `zip` binary is not reliably present on
#     Windows). Invoked as `python3 -B` so no __pycache__ is created.
#   * adb on PATH for --install / --uninstall.
#
# THE REPOSITORY SHIPS SOURCES, NEVER BINARIES.
#   Everything this script produces lands under $OUTDIR, which defaults to a
#   temporary directory OUTSIDE the repository. The two signing keys are
#   generated there on the spot; no key, certificate, .apk, .dex or .class is
#   ever written next to these sources.
#
# GIT BASH / MSYS TRAPS -- both cost real time in this repository before
#   1. SDK tools are native Windows binaries and do not understand /c/Users
#      paths. Every path handed to one goes through cygpath -w (the p() helper).
#      Without it aapt2 reports "failed to load XML file" for a file that plainly
#      exists. This repository lives under a directory with a space in its name,
#      so the quoting matters as well.
#   2. `adb push` mangles an absolute remote path under MSYS. MSYS_NO_PATHCONV=1
#      is set for adb calls that carry one.
#   3. XML comments must not contain a double hyphen; aapt2 rejects the file.
#
# AUTHORISED TESTING ONLY. vault-target holds fixture secrets and vault-probe
# reads another package's private data by design. Install both only on a device
# you own, and run --uninstall when you are finished.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch66-build}"

TARGET_PKG="com.pentest.ch66.vault"
TEST_PKG="com.pentest.ch66.vault.test"

p() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

# --------------------------------------------------------------------------- #
# Locate the SDK and the JDK
# --------------------------------------------------------------------------- #
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$SDK" ]; then
    for c in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "${LOCALAPPDATA:-}/Android/Sdk"; do
        [ -d "$c" ] && SDK="$c" && break
    done
fi
[ -d "${SDK:-}" ] || { echo "error: set ANDROID_HOME to your Android SDK"; exit 2; }

BT="$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)"
AJ="$(ls -d "$SDK"/platforms/*/android.jar 2>/dev/null | sort -V | tail -1)"
[ -n "$BT" ] || { echo "error: no build-tools under $SDK"; exit 2; }
[ -n "$AJ" ] || { echo "error: no platform android.jar under $SDK"; exit 2; }

pick() {
    for cand in "$BT/$1" "$BT/$1.bat" "$BT/$1.exe"; do
        [ -f "$cand" ] && { echo "$cand"; return; }
    done
    echo "$BT/$1"
}
AAPT2="$(pick aapt2)"; D8="$(pick d8)"
ZIPALIGN="$(pick zipalign)"; APKSIGNER="$(pick apksigner)"

command -v javac  >/dev/null 2>&1 || { echo "error: javac not on PATH"; exit 2; }
command -v keytool >/dev/null 2>&1 || { echo "error: keytool not on PATH"; exit 2; }
PY="python3"; command -v python3 >/dev/null 2>&1 || PY="python"

echo "SDK          $SDK"
echo "build-tools  $(basename "$BT")"
echo "android.jar  $AJ"
echo "javac        $(javac -version 2>&1)"
echo "outdir       $OUTDIR"
echo

mkdir -p "$OUTDIR"

# --------------------------------------------------------------------------- #
# Two throwaway signing keys, both generated into $OUTDIR.
#
# Key A signs the target and the matching probe. Key B signs nothing but the
# mismatched probe. Two keys is the entire experimental apparatus for the
# signature question, and it costs four lines.
# --------------------------------------------------------------------------- #
mkkey() {
    local ks="$1" alias="$2"
    [ -f "$ks" ] && return 0
    keytool -genkeypair -keystore "$(p "$ks")" -storepass android -keypass android \
        -alias "$alias" -dname "CN=CH66 $alias,O=Android Pentesting Notes" \
        -validity 10000 -keyalg RSA -keysize 2048 >/dev/null 2>&1 \
        || { echo "error: keytool failed for $alias"; exit 2; }
    echo "generated signing key $alias at $ks"
}
KS_A="$OUTDIR/keyA.ks"; mkkey "$KS_A" ch66a
KS_B="$OUTDIR/keyB.ks"; mkkey "$KS_B" ch66b

# --------------------------------------------------------------------------- #
# build_apk <work-name> <src-dir> <java-package-path> <manifest> <keystore>
#           <key-alias> <extra-aapt2-args...>
# --------------------------------------------------------------------------- #
build_apk() {
    local name="$1"; shift
    local src="$1"; shift
    local pkgpath="$1"; shift
    local manifest="$1"; shift
    local ks="$1"; shift
    local alias="$1"; shift

    local work="$OUTDIR/$name"
    echo "=== $name ==="
    rm -rf "$work"
    mkdir -p "$work/src/$pkgpath" "$work/classes"

    cp "$src"/*.java "$work/src/$pkgpath/" 2>/dev/null || {
        echo "error: no .java under $src"; return 1; }

    "$AAPT2" link -o "$(p "$work/base.apk")" -I "$(p "$AJ")" \
        --manifest "$(p "$manifest")" \
        --min-sdk-version 24 --target-sdk-version 35 "$@" || return 1

    javac --release 8 -nowarn -classpath "$(p "$AJ")" \
        -d "$(p "$work/classes")" "$work/src/$pkgpath"/*.java \
        2>&1 | grep -vE 'deprecat|obsolete|Xlint|^Note:|bootstrap class path'

    local classfiles=()
    while IFS= read -r f; do classfiles+=("$(p "$f")"); done \
        < <(find "$work/classes" -name '*.class')
    [ ${#classfiles[@]} -gt 0 ] || { echo "error: javac produced no classes"; return 1; }

    # d8 is handed the class files as ordinary argv entries. It does NOT share
    # javac's @argfile grammar, even though both ship in the same toolchain:
    # javac splits an argfile on whitespace and HONOURS double quotes, while d8
    # does not strip them and hands the quote straight to java.nio, failing with
    #   InvalidPathException: Illegal char <"> at index 0
    # naming a path that is plainly correct apart from the quotes you added to
    # make javac work. This repository lives under a directory whose name
    # contains a space, so both halves fire. Do not "simplify" this into an
    # argfile; if you need one, hand d8 a jar instead -- which is also what a
    # real Gradle build does.
    "$D8" --lib "$(p "$AJ")" --min-api 24 --output "$(p "$work")" "${classfiles[@]}" || return 1

    ( cd "$work" && "$PY" -B -c "
import zipfile, shutil
shutil.copy('base.apk', 'unaligned.apk')
z = zipfile.ZipFile('unaligned.apk', 'a', zipfile.ZIP_DEFLATED)
z.write('classes.dex', 'classes.dex')
z.close()
" ) || return 1

    "$ZIPALIGN" -f -p 4 "$(p "$work/unaligned.apk")" "$(p "$work/aligned.apk")" || return 1
    "$APKSIGNER" sign --ks "$(p "$ks")" --ks-pass pass:android --key-pass pass:android \
        --ks-key-alias "$alias" \
        --out "$(p "$OUTDIR/$name.apk")" "$(p "$work/aligned.apk")" 2>&1 | grep -v WARNING

    echo "built $OUTDIR/$name.apk"
    echo
}

# --------------------------------------------------------------------------- #
# Derive the testOnly manifest. android:testOnly="true" is not an aapt2 flag --
# Gradle writes it into the manifest for `assembleAndroidTest`, so we do the same.
# --------------------------------------------------------------------------- #
TESTONLY_MANIFEST="$OUTDIR/AndroidManifest-testonly.xml"
sed 's|<application android:label="ch66 vault probe" />|<application android:label="ch66 vault probe" android:testOnly="true" />|' \
    "$HERE/vault-probe/AndroidManifest.xml" > "$TESTONLY_MANIFEST"
grep -q 'testOnly' "$TESTONLY_MANIFEST" || {
    echo "error: testOnly substitution failed -- did the manifest change?"; exit 2; }

MODE="${1:-}"

case "$MODE" in
    --uninstall)
        MSYS_NO_PATHCONV=1 adb uninstall "$TEST_PKG"   2>&1 | tail -1
        MSYS_NO_PATHCONV=1 adb uninstall "$TARGET_PKG" 2>&1 | tail -1
        exit 0
        ;;
esac

# --------------------------------------------------------------------------- #
# The five artefacts
# --------------------------------------------------------------------------- #
build_apk vault-release   "$HERE/vault-target" com/pentest/ch66/vault \
          "$HERE/vault-target/AndroidManifest.xml" "$KS_A" ch66a || exit 1

build_apk vault-debuggable "$HERE/vault-target" com/pentest/ch66/vault \
          "$HERE/vault-target/AndroidManifest.xml" "$KS_A" ch66a --debug-mode || exit 1

build_apk probe-sigA      "$HERE/vault-probe" com/pentest/ch66/probe \
          "$HERE/vault-probe/AndroidManifest.xml" "$KS_A" ch66a || exit 1

build_apk probe-sigB      "$HERE/vault-probe" com/pentest/ch66/probe \
          "$HERE/vault-probe/AndroidManifest.xml" "$KS_B" ch66b || exit 1

build_apk probe-testonly  "$HERE/vault-probe" com/pentest/ch66/probe \
          "$TESTONLY_MANIFEST" "$KS_A" ch66a || exit 1

# --------------------------------------------------------------------------- #
# Prove the one bit that is supposed to differ actually differs.
# A fixture you have not verified is a fixture that will teach you the wrong
# thing quietly. It is the same failure as measuring from the wrong vantage --
# the most repeated finding in this repository: the same probe answers
# differently as root, as `adb shell` (uid 2000) and as the app, and nothing in
# the output says which one you got. This chapter measured the sharpest case:
# inside ONE instrumented process at uid 10210, /system/xbin/su, /proc/modules
# and /data/local/tmp were all EACCES to the app's own reads and all three came
# back readable via UiAutomation.executeShellCommand, which runs as uid 2000.
# --------------------------------------------------------------------------- #
echo "=== fixture self-check ==="
for a in vault-release vault-debuggable; do
    printf '%-18s debuggable=' "$a"
    "$AAPT2" dump xmltree --file AndroidManifest.xml "$(p "$OUTDIR/$a.apk")" 2>/dev/null \
        | grep -c 'debuggable' | tr -d '\r'
done
printf '%-18s testOnly=' probe-testonly
"$AAPT2" dump xmltree --file AndroidManifest.xml "$(p "$OUTDIR/probe-testonly.apk")" 2>/dev/null \
    | grep -c 'testOnly' | tr -d '\r'
printf '%-18s testOnly=' probe-sigA
"$AAPT2" dump xmltree --file AndroidManifest.xml "$(p "$OUTDIR/probe-sigA.apk")" 2>/dev/null \
    | grep -c 'testOnly' | tr -d '\r'
echo
echo "signer digests (these must differ between sigA and sigB):"
for a in vault-release probe-sigA probe-sigB; do
    printf '  %-16s ' "$a"
    "$APKSIGNER" verify --print-certs "$(p "$OUTDIR/$a.apk")" 2>/dev/null \
        | grep -i 'SHA-256 digest' | head -1
done
echo

if [ "$MODE" = "--install" ]; then
    echo "=== installing vault-debuggable + probe-sigA ==="
    MSYS_NO_PATHCONV=1 adb install -r "$(p "$OUTDIR/vault-debuggable.apk")" 2>&1 | tail -1
    MSYS_NO_PATHCONV=1 adb install -r "$(p "$OUTDIR/probe-sigA.apk")"       2>&1 | tail -1
    echo
    echo "now:  adb shell pm list instrumentation"
    echo "then: adb shell am instrument -w -r $TEST_PKG/com.pentest.ch66.probe.VaultProbe"
fi

echo "done. Artefacts are under $OUTDIR -- nothing was written into the repository."
