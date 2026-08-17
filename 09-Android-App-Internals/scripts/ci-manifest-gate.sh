#!/usr/bin/env bash
# scripts/ci-manifest-gate.sh
#
# WHAT IT DOES
#   Fails the build if a release APK violates any of the identity/sandbox rules from
#   chapter 09: debuggable, sharedUserId without a max-SDK cap, allowBackup with no
#   extraction rules, an unexpectedly low targetSdkVersion, or a cleartext-traffic opt-in.
#
# HOW TO RUN
#   ./scripts/ci-manifest-gate.sh app-release.apk 34
#
set -euo pipefail

APK="${1:?usage: ci-manifest-gate.sh <apk> <min-target-sdk>}"
MIN_TARGET="${2:-34}"
TREE=$(mktemp)
aapt2 dump xmltree "$APK" --file AndroidManifest.xml > "$TREE"
FAIL=0

fail() { echo "FAIL: $*" >&2; FAIL=1; }
pass() { echo "ok  : $*"; }

# 1. Debuggable release builds. Section 5.4.
if grep -qiE 'android:debuggable\(0x0101000f\)=\(type 0x12\)0xffffffff' "$TREE"; then
  fail "android:debuggable=\"true\" in a release APK"
else
  pass "not debuggable"
fi

# 2. sharedUserId without sharedUserMaxSdkVersion. Section 5.3.
if grep -qi 'sharedUserId' "$TREE"; then
  if grep -qi 'sharedUserMaxSdkVersion' "$TREE"; then
    pass "sharedUserId present but capped with sharedUserMaxSdkVersion"
  else
    fail "sharedUserId declared with no sharedUserMaxSdkVersion cap"
  fi
else
  pass "no sharedUserId"
fi

# 3. allowBackup with no data-extraction rules. Section 3.10 / MASVS-STORAGE-2.
if grep -qiE 'allowBackup\(0x[0-9a-f]+\)=\(type 0x12\)0xffffffff' "$TREE"; then
  if grep -qiE 'dataExtractionRules|fullBackupContent' "$TREE"; then
    pass "backup enabled with explicit rules"
  else
    fail "android:allowBackup=\"true\" with no dataExtractionRules/fullBackupContent"
  fi
else
  pass "backup disabled or explicitly configured"
fi

# 4. targetSdkVersion floor. Section 8.3.
TARGET=$(aapt2 dump badging "$APK" | sed -n "s/.*targetSdkVersion:'\([0-9]*\)'.*/\1/p")
if [ -z "$TARGET" ] || [ "$TARGET" -lt "$MIN_TARGET" ]; then
  fail "targetSdkVersion=${TARGET:-unset} is below the required $MIN_TARGET"
else
  pass "targetSdkVersion=$TARGET"
fi

# 5. Cleartext traffic opt-in.
if grep -qiE 'usesCleartextTraffic\(0x[0-9a-f]+\)=\(type 0x12\)0xffffffff' "$TREE"; then
  fail "android:usesCleartextTraffic=\"true\""
else
  pass "cleartext traffic not globally enabled"
fi

# 6. Inventory every provider that will run before Application.onCreate(). Section 5.6.
echo
echo "Providers that will run at process start (review this list):"
grep -A 4 'E: provider' "$TREE" | grep 'android:name' | sed 's/.*="\(.*\)".*/  \1/' | sort -u

rm -f "$TREE"
exit "$FAIL"
