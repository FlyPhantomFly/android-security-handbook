#!/bin/sh
# 05-runtime-baseline.sh — capture a build-matched runtime baseline for one app.
#
# WHAT IT DOES
#   Records the device build, the app's UID/SELinux context/mount namespace,
#   executable mappings, open file descriptors and a few class-loader facts.
#   It is a baseline collector, not a detector: the output is meant to be
#   diffed against a run with the suspected loader or hook enabled.
#
# HOW TO RUN
#   # host — from the repository root
#   sh 81-Android-Runtime-Internals/examples/05-runtime-baseline.sh com.example.target > baseline.txt
#
#   # then enable the variable and capture again
#   sh 81-Android-Runtime-Internals/examples/05-runtime-baseline.sh com.example.target > hooked.txt
#   diff -u baseline.txt hooked.txt
#
# REQUIREMENTS
#   adb, a rooted lab device, and the root form that works on it. This script
#   uses `su 0`; change ROOT if your device differs.

set -u

PKG="${1:-}"
ROOT="su 0"
OUT_TAG="runtime-baseline"

if [ -z "$PKG" ]; then
    echo "usage: $0 <package>" >&2
    exit 2
fi

say() {
    printf '\n== %s ==\n' "$1"
}

run() {
    # shellcheck disable=SC2086
    adb shell "$@"
}

PID="$(adb shell pidof "$PKG" | tr -d '\r' | awk '{print $1}')"
if [ -z "$PID" ]; then
    echo "no running process for $PKG; start the app first" >&2
    exit 1
fi

say "$OUT_TAG"
echo "package: $PKG"
echo "pid: $PID"
echo "captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

say "build"
run "getprop ro.build.fingerprint"
run "getprop ro.build.version.sdk"
run "getprop ro.product.cpu.abi"
run "getprop ro.build.version.security_patch"

say "identity"
run "$ROOT grep -E '^(Uid|Gid|TracerPid):' /proc/$PID/status"
run "$ROOT cat /proc/$PID/attr/current"
run "$ROOT readlink /proc/$PID/ns/mnt"

say "executable mappings"
run "$ROOT awk '\$2 ~ /x/ {print \$1, \$2, \$6}' /proc/$PID/maps" | sort -u

say "memfd and deleted mappings"
run "$ROOT grep -E 'memfd|deleted' /proc/$PID/maps" || true

say "file descriptors"
run "$ROOT ls -l /proc/$PID/fd" | head -60

say "cmdline"
run "$ROOT tr '\0' ' ' < /proc/$PID/cmdline" || true

say "loader indicators"
run "$ROOT grep -E 'zygisk|lsplant|vector|lsposed|frida|gum|libzgn' /proc/$PID/maps" || true

say "done"
echo "diff this file against a run with the variable changed."
echo "state the vantage: app, shell, root, or offline image."
