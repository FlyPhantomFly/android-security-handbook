#!/usr/bin/env bash
#
# examples/build.sh -- turn the sources in this directory into two installable
#                      APKs: the vulnerable target and the attacker.
#
# PURPOSE
#   This repository ships SOURCES, never built APKs. A .apk in a git tree is an
#   artefact nobody can audit and everybody has to trust. This script produces
#   them locally, in one command, from files you can read.
#
# WHAT IT BUILDS
#   vulnerable-app/  com.example.vault    -- ConfigSyncReceiver-vulnerable.java,
#                    VaultApplication.java, AndroidManifest-vulnerable.xml
#   attacker-app/    com.attacker.bcast   -- AttackerBroadcaster.java
#   ctf-app/         com.example.vaultctf -- CtfVaultReceivers.java (--ctf)
#
#   Pass --fixed to build the remediated variant instead, so you can run the
#   same attacks against both and watch them stop working.
#
#   Pass --ctf to build the target for labs/lab-04. That variant needs a
#   manifest you write yourself, AndroidManifest-ctf.xml, and this script tells
#   you exactly what it must contain if the file is missing. Writing it is part
#   of the exercise: it forces you to decide which components MUST be declared
#   and which must not, which is the whole question chapter 29 is about.
#
# WHAT THIS WILL *NOT* DO
#   * It will not install anything. Installation is a separate, deliberate step,
#     and on the device this chapter was measured against it fails anyway --
#     see the note below.
#   * It will not sign with a release key. The debug keystore is generated on
#     first use, which is correct for a lab and wrong for anything else.
#   * It will not check your work. A build that succeeds proves the sources
#     compile, nothing more.
#
# REQUIREMENTS
#   A JDK (17 or newer), and either
#     (a) the Android SDK with a recent build-tools and platform installed, with
#         ANDROID_HOME or ANDROID_SDK_ROOT set -- this script uses aapt2, d8 and
#         apksigner directly, no Gradle; or
#     (b) Gradle plus the Android Gradle Plugin, if you prefer to generate a
#         project and build that instead. The direct path is faster and has
#         fewer moving parts.
#
# THE INSTALL RESTRICTION YOU WILL PROBABLY HIT
#   The physical device used to measure this chapter -- a Redmi M2101K6P
#   (sweetin), MIUI 12.5, Android 11 / API 30 -- refuses every `adb install`
#   with
#       INSTALL_FAILED_USER_RESTRICTED
#   This is an OEM policy ("Install via USB" is disabled behind a Xiaomi account
#   check), not a defect in the APK and not something a rebuild fixes. If you
#   see it:
#     * use an emulator (`avdmanager` / Android Studio) for the lab work; or
#     * enable the vendor's "Install via USB" developer option; or
#     * do the enumeration labs, which need no installed app at all, against the
#       real device, and the exploitation labs on the emulator.
#   Labs 01 and 03 in this chapter were written specifically so that the parts
#   that need no APK still run on a restricted device.
#
# USAGE
#   ./build.sh              # vulnerable variant
#   ./build.sh --fixed      # remediated variant
#   ./build.sh --ctf        # the lab-04 CTF target
#   ./build.sh --clean
#
# AUTHORISED TESTING ONLY.

set -eu

VARIANT="vulnerable"
[ "${1:-}" = "--fixed" ] && VARIANT="fixed"
[ "${1:-}" = "--ctf" ] && VARIANT="ctf"

if [ "${1:-}" = "--clean" ]; then
    rm -rf build/
    echo "cleaned."
    exit 0
fi

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
[ -n "$SDK" ] || { echo "set ANDROID_HOME or ANDROID_SDK_ROOT" >&2; exit 1; }

# Newest build-tools and newest platform, rather than a pinned version, so this
# keeps working as the SDK is updated.
BT="$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)"
PLATFORM="$(ls -d "$SDK"/platforms/android-* 2>/dev/null | sort -V | tail -1)"
[ -n "$BT" ] || { echo "no build-tools under $SDK" >&2; exit 1; }
[ -n "$PLATFORM" ] || { echo "no platform under $SDK" >&2; exit 1; }

AAPT2="$BT/aapt2"
D8="$BT/d8"
APKSIGNER="$BT/apksigner"
ZIPALIGN="$BT/zipalign"
ANDROID_JAR="$PLATFORM/android.jar"

echo "build-tools : $BT"
echo "platform    : $PLATFORM"
echo "variant     : $VARIANT"
echo ""

DEBUG_KEY="$HOME/.android/debug.keystore"
if [ ! -f "$DEBUG_KEY" ]; then
    echo "generating a debug keystore..."
    mkdir -p "$HOME/.android"
    keytool -genkeypair -v -keystore "$DEBUG_KEY" -storepass android \
        -alias androiddebugkey -keypass android \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Android Debug,O=Android,C=US" >/dev/null
fi

build_one() {
    # $1 = output name, $2 = manifest file, $3.. = java sources
    local name="$1"; shift
    local manifest="$1"; shift
    local out="build/$name"

    echo "=== $name ==="
    rm -rf "$out"
    mkdir -p "$out/classes" "$out/res" "$out/dex"

    # 1. Compile resources (there are none) and link the manifest.
    "$AAPT2" link \
        -I "$ANDROID_JAR" \
        --manifest "$manifest" \
        --java "$out/gen" \
        -o "$out/base.apk" \
        >/dev/null

    # 2. Compile Java against android.jar.
    javac -source 8 -target 8 -nowarn \
        -bootclasspath "$ANDROID_JAR" \
        -classpath "$ANDROID_JAR" \
        -d "$out/classes" "$@" 2>&1 | grep -v "bootstrap class path" || true

    # 3. Java bytecode to DEX.
    "$D8" --lib "$ANDROID_JAR" --output "$out/dex" \
        $(find "$out/classes" -name '*.class') >/dev/null

    # 4. Put classes.dex into the linked APK.
    ( cd "$out/dex" && zip -q "../base.apk" classes.dex )

    # 5. Align, then sign. Order matters: apksigner must run last.
    "$ZIPALIGN" -f 4 "$out/base.apk" "$out/aligned.apk"
    "$APKSIGNER" sign --ks "$DEBUG_KEY" --ks-pass pass:android \
        --key-pass pass:android --out "build/$name.apk" "$out/aligned.apk"

    echo "  -> build/$name.apk"
    echo ""
}

mkdir -p build

if [ "$VARIANT" = "fixed" ]; then
    build_one vault-fixed AndroidManifest-fixed.xml \
        ConfigSyncReceiver-fixed.java VaultApplication.java

elif [ "$VARIANT" = "ctf" ]; then
    if [ ! -f AndroidManifest-ctf.xml ]; then
        cat <<'MSG'
AndroidManifest-ctf.xml does not exist, and writing it is part of lab 04.

It needs exactly four things, and no more:

  package="com.example.vaultctf"
  <application android:name=".CtfApplication">
  <activity android:name=".MainActivity" android:exported="true"> with a
      MAIN/LAUNCHER intent-filter
  <receiver android:name=".Flag2Receiver" android:exported="true"> with an
      intent-filter listing THREE actions:
        android.intent.action.BOOT_COMPLETED
        android.intent.action.LOCALE_CHANGED
        com.example.vaultctf.REFRESH

Note what must NOT be in it. CtfApplication registers three more receivers at
runtime, and if you declare any of them the CTF's first flag stops being a
puzzle -- which is the lesson. A manifest is a lower bound on the broadcast
surface, not an inventory of it.

Write the file, then run ./build.sh --ctf again.
MSG
        exit 1
    fi
    build_one vault-ctf AndroidManifest-ctf.xml CtfVaultReceivers.java

else
    build_one vault-vulnerable AndroidManifest-vulnerable.xml \
        ConfigSyncReceiver-vulnerable.java VaultApplication.java
fi

echo "Attacker app: AttackerBroadcaster.java needs its own manifest declaring"
echo "com.attacker.bcast/.MainActivity as the launcher. Write a four-line"
echo "manifest for it and call build_one the same way -- deliberately left as"
echo "an exercise, because writing that manifest is how you learn what the"
echo "attacker app does and does NOT need (answer: no permissions at all)."
echo ""
echo "Then:"
echo "  adb install -r build/vault-vulnerable.apk"
echo "  python3 ../scripts/receiver-surface.py --package com.example.vault"
echo "  frida -U -f com.example.vault -l ../scripts/hook-broadcast.js"
