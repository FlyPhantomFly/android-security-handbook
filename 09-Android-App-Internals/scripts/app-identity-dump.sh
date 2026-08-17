#!/usr/bin/env bash
# scripts/app-identity-dump.sh
#
# WHAT IT DOES
#   Collects, for one installed package, every identity, storage and process fact from
#   chapter 09 into a single report: appId/UID, shared user, GIDs, SELinux label, data
#   directories, code paths and splits, provenance, per-user state, and the process list.
#
# HOW TO RUN
#   ./scripts/app-identity-dump.sh com.example.app          (root recommended, not required)
#
# REQUIREMENTS
#   bash on the host, adb on PATH, exactly one device connected. Root on the device is
#   optional: the data-directory and packages.list sections need it and print "(no root)"
#   without it; everything else works as uid 2000 (shell). Nothing is installed, nothing
#   is modified — this script only reads.
#
# WHAT THIS WILL NOT TELL YOU
#   - Nothing here reads the APK. Signing certificates, the merged manifest, DEX contents
#     and native libraries are out of scope; pull the splits with `pm path` and use
#     `apksigner verify --print-certs` and `aapt2 dump xmltree` for those.
#   - It reports only user 0. On a device with a work profile the same package also exists
#     as userId 10 with UID 1010234-style numbering, and none of it appears below. Re-run
#     the underlying commands with `--user 10` (see faq.md question 16).
#   - `gids=` from dumpsys is what PackageManagerService recorded, not necessarily what the
#     kernel gave a live process. `Groups:` in the /proc section is the ground truth; when
#     the two disagree, the kernel wins.
#   - It shows THAT a provider is registered, not what its onCreate() does. For execution
#     order and behaviour use scripts/trace-app-startup.js.
#   - It says nothing about whether the sandbox is actually ENFORCED against a given
#     attacker — that is chapter 21's question, not chapter 09's. See
#     ../../21-App-Sandbox/README.md.
#   - Absence of output from a section means "the command returned nothing", which can be
#     a missing package, a missing root shell or a genuinely empty result. Check by hand
#     before reporting an absence as a finding.
#
set -u
PKG="${1:?usage: app-identity-dump.sh <package>}"
run() { adb shell "$@" 2>/dev/null | tr -d '\r'; }

echo "=== package ==============================================="
run pm list packages -U | grep -w "package:$PKG"
echo
echo "=== record ================================================"
run dumpsys package "$PKG" | grep -E \
  'userId=|sharedUser|flags=\[|privateFlags=\[|versionCode=|targetSdk|codePath=|resourcePath=|splits=|dataDir=|primaryCpuAbi=|installerPackageName|installInitiator|originating|packageSource|firstInstallTime|lastUpdateTime|apkSigningVersion|gids='
echo
echo "=== per-user state ========================================"
run dumpsys package "$PKG" | grep -E '^\s+User [0-9]+:' -A 2
echo
echo "=== code paths ============================================"
run pm path "$PKG"
echo
echo "=== processes ============================================="
run ps -A -Z -o LABEL,USER,PID,PPID,NAME | grep "$PKG"
echo
echo "=== /proc (first pid) ====================================="
PID=$(run pidof "$PKG" | awk '{print $1}')
if [ -n "${PID:-}" ]; then
  run cat "/proc/$PID/status" | grep -E '^(Name|State|Uid|Gid|Groups|TracerPid|Threads|VmRSS)'
  run cat "/proc/$PID/attr/current"
  run cat "/proc/$PID/oom_score_adj"
else
  echo "(no running process)"
fi
echo
echo "=== data directories (root) ==============================="
# NOTE: the whole `su -c` invocation must reach the device as ONE argument, otherwise adb
# joins the words itself and `su -c` receives only "ls".
DIRS=$(run "su -c 'ls -ldZ /data/user/0/$PKG /data/user_de/0/$PKG'")
[ -n "$DIRS" ] && echo "$DIRS" || echo "(no root, or no data directories)"
run "ls -la /sdcard/Android/data/$PKG" || true
echo
echo "=== packages.list (root) =================================="
PLIST=$(run "su -c 'grep -w \"^$PKG\" /data/system/packages.list'")
[ -n "$PLIST" ] && echo "$PLIST" || echo "(no root, or no record)"
echo
echo "=== providers that run at startup ========================="
run dumpsys package "$PKG" | sed -n '/Provider Resolver Table/,/Service Resolver Table/p'
